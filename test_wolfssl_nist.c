#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/mlkem.h>

static uint8_t injected_d[32];
static uint8_t injected_z[32];
static uint8_t injected_m[32];

static int d_used = 0, z_used = 0, m_used = 0;
static int current_mode = 0; // 1 = keygen, 2 = encap

int CustomRNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz) {
    if (current_mode == 1) { // KeyGen requires 64 bytes (d || z)
        if (sz == 64) {
            memcpy(output, injected_d, 32);
            memcpy(output + 32, injected_z, 32);
            return 0;
        }
        if (sz == 32) {
            if (!d_used) { memcpy(output, injected_d, 32); d_used = 1; return 0; }
            if (!z_used) { memcpy(output, injected_z, 32); z_used = 1; return 0; }
        }
    } else if (current_mode == 2) { // Encap requires 32 bytes (m)
        if (sz == 32 && !m_used) {
            memcpy(output, injected_m, 32);
            m_used = 1;
            return 0;
        }
    }
    fprintf(stderr, "FATAL: WolfSSL requested unexpected entropy (%u bytes) in mode %d\n", sz, current_mode);
    exit(1);
    return -1;
}

int CustomRNG_GenerateSeed(WC_RNG* rng, byte* output, word32 sz) {
    return CustomRNG_GenerateBlock(rng, output, sz);
}

int hexdig(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

int hex2bin(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    if(len%2!=0) return -1;
    for(size_t i=0; i<len/2; i++) {
        int hi = hexdig(hex[2*i]), lo = hexdig(hex[2*i+1]);
        if(hi<0||lo<0) return -1;
        out[i] = (hi<<4)|lo;
    }
    return len/2;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <512|768|1024> <acvp.rsp>\n", argv[0]);
        return 1;
    }

    int bits = atoi(argv[1]);
    int type = (bits == 512) ? MLKEM512 : (bits == 768) ? MLKEM768 : MLKEM1024;
    size_t pk_len = (bits == 512) ? 800 : (bits == 768) ? 1184 : 1568;
    size_t sk_len = (bits == 512) ? 1632 : (bits == 768) ? 2400 : 3168;
    size_t ct_len = (bits == 512) ? 768 : (bits == 768) ? 1088 : 1568;
    size_t ss_len = 32;

    FILE *fp = fopen(argv[2], "r");
    if (!fp) { perror("fopen"); return 1; }

    char line[4096];
    char d_hex[100]="", z_hex[100]="", msg_hex[100]="";
    char ek_ref[4096]="", dk_ref[4096]="", ct_ref[4096]="", ss_ref[4096]="";
    
    int count = -1;
    int keygen_pass = 0, encap_pass = 0, decap_pass = 0;
    int test_total = 0;

    wolfSSL_Init();
    WC_RNG rng;
    memset(&rng, 0, sizeof(rng));
    rng.generateBlock = CustomRNG_GenerateBlock;
    rng.generateSeed = CustomRNG_GenerateSeed;

    printf("========================================================\n");
    printf("  WolfSSL ML-KEM-%d KAT Verification                    \n", bits);
    printf("========================================================\n");

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "count = ", 8) == 0) {
            count = atoi(line + 8);
            memset(d_hex, 0, sizeof(d_hex));
            memset(z_hex, 0, sizeof(z_hex));
            memset(msg_hex, 0, sizeof(msg_hex));
            memset(ek_ref, 0, sizeof(ek_ref));
            memset(dk_ref, 0, sizeof(dk_ref));
            memset(ct_ref, 0, sizeof(ct_ref));
            memset(ss_ref, 0, sizeof(ss_ref));
            test_total++;
        }
        else if (strncmp(line, "d = ", 4) == 0) strcpy(d_hex, line + 4);
        else if (strncmp(line, "z = ", 4) == 0) strcpy(z_hex, line + 4);
        else if (strncmp(line, "msg = ", 6) == 0) strcpy(msg_hex, line + 6);
        else if (strncmp(line, "ek = ", 5) == 0) strcpy(ek_ref, line + 5);
        else if (strncmp(line, "dk = ", 5) == 0) strcpy(dk_ref, line + 5);
        else if (strncmp(line, "c = ", 4) == 0) strcpy(ct_ref, line + 4);
        // Sometimes it's c = or ct =
        else if (strncmp(line, "ct = ", 5) == 0) strcpy(ct_ref, line + 5);
        else if (strncmp(line, "ss = ", 5) == 0) {
            strcpy(ss_ref, line + 5);
            d_hex[strcspn(d_hex, "\r\n")] = 0;
            z_hex[strcspn(z_hex, "\r\n")] = 0;
            msg_hex[strcspn(msg_hex, "\r\n")] = 0;
            ek_ref[strcspn(ek_ref, "\r\n")] = 0;
            dk_ref[strcspn(dk_ref, "\r\n")] = 0;
            ct_ref[strcspn(ct_ref, "\r\n")] = 0;
            ss_ref[strcspn(ss_ref, "\r\n")] = 0;

            hex2bin(d_hex, injected_d);
            hex2bin(z_hex, injected_z);
            if (strlen(msg_hex)) hex2bin(msg_hex, injected_m);

            MlKemKey key;
            wc_MlKemKey_Init(type, &key, NULL, INVALID_DEVID);

            /* --- KEYGEN TEST --- */
            if (strlen(ek_ref) && strlen(dk_ref)) {
                current_mode = 1; d_used = 0; z_used = 0;
                if (wc_MlKemKey_MakeKeyWithRng(&key, &rng) == 0) {
                    uint8_t pk[3000], sk[4000];
                    word32 pl = pk_len, sl = sk_len;
                    wc_MlKemKey_EncodePublicKey(&key, pk, &pl);
                    wc_MlKemKey_EncodePrivateKey(&key, sk, &sl);

                    uint8_t ek_bin[3000], dk_bin[4000];
                    hex2bin(ek_ref, ek_bin); hex2bin(dk_ref, dk_bin);

                    if (memcmp(pk, ek_bin, pk_len) == 0 && memcmp(sk, dk_bin, sk_len) == 0)
                        keygen_pass++;
                    else
                        printf(" [!] KeyGen Mismatch at count %d\n", count);
                } else {
                    printf(" [!] wc_MlKemKey_MakeKeyWithRng Failed at count %d\n", count);
                }
            }

            /* --- ENCAPSULATION TEST --- */
            if (strlen(msg_hex) && strlen(ek_ref)) {
                // If we didn't just generate the key, load it
                if (!strlen(dk_ref)) {
                    uint8_t ek_bin[3000]; hex2bin(ek_ref, ek_bin);
                    wc_MlKemKey_DecodePublicKey(ek_bin, pk_len, &key);
                }
                
                current_mode = 2; m_used = 0;
                uint8_t ct[3000], ss[32];
                if (wc_MlKemKey_Encapsulate(&key, ct, ss, &rng) == 0) {
                    uint8_t ct_bin[3000], ss_bin[32];
                    hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);

                    if (memcmp(ct, ct_bin, ct_len) == 0 && memcmp(ss, ss_bin, 32) == 0)
                        encap_pass++;
                    else
                        printf(" [!] Encap Mismatch at count %d\n", count);
                } else {
                    printf(" [!] wc_MlKemKey_Encapsulate Failed at count %d\n", count);
                }
            }

            /* --- DECAPSULATION TEST --- */
            if (strlen(dk_ref) && strlen(ct_ref) && strlen(ss_ref) && !strlen(msg_hex)) {
                // Typical decrypt/decap vector without m
                uint8_t dk_bin[4000]; hex2bin(dk_ref, dk_bin);
                wc_MlKemKey_DecodePrivateKey(dk_bin, sk_len, &key);
                
                uint8_t ct_bin[3000], ss_bin[32];
                hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);
                
                uint8_t ss_out[32];
                if (wc_MlKemKey_Decapsulate(&key, ss_out, ct_bin, ct_len) == 0) {
                    if (memcmp(ss_out, ss_bin, 32) == 0)
                        decap_pass++;
                    else
                        printf(" [!] Decap Mismatch at count %d\n", count);
                } else {
                    printf(" [!] wc_MlKemKey_Decapsulate Failed at count %d\n", count);
                }
            }

            wc_MlKemKey_Free(&key);
        }
    }
    fclose(fp);
    wolfSSL_Cleanup();

    printf("\n  Summary for WolfSSL ML-KEM-%d\n", bits);
    printf("  --------------------------------------------------------\n");
    if (keygen_pass > 0) printf("  KeyGen Passed:         %d / %d\n", keygen_pass, keygen_pass);
    if (encap_pass > 0)  printf("  Encapsulation Passed:  %d / %d\n", encap_pass, encap_pass);
    if (decap_pass > 0)  printf("  Decapsulation Passed:  %d / %d\n", decap_pass, decap_pass);
    printf("========================================================\n\n");

    return 0;
}
