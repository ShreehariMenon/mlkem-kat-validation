#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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
        unsigned int val;
        sscanf(hex + 2*i, "%2x", &val);
        out[i] = (uint8_t)val;
    }
    return len/2;
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int bits = atoi(argv[1]);
    
    int type = (bits == 512) ? WC_ML_KEM_512 : (bits == 768) ? WC_ML_KEM_768 : WC_ML_KEM_1024;
    
    size_t pk_len = (bits == 512) ? 800 : (bits == 768) ? 1184 : 1568;
    size_t sk_len = (bits == 512) ? 1632 : (bits == 768) ? 2400 : 3168;
    size_t ct_len = (bits == 512) ? 768 : (bits == 768) ? 1088 : 1568;

    FILE *fp = fopen(argv[2], "r");
    if (!fp) return 1;

    char line[4096];
    char d_hex[100]="", z_hex[100]="", msg_hex[100]="";
    char ek_ref[4096]="", dk_ref[4096]="", ct_ref[4096]="", ss_ref[4096]="";
    
    int count = -1, keygen_pass = 0, encap_pass = 0, decap_pass = 0;

    printf("========================================================\n");
    printf("  WolfSSL ML-KEM-%d KAT Verification                    \n", bits);
    printf("========================================================\n");

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "count = ", 8) == 0) {
            count = atoi(line + 8);
            memset(d_hex, 0, sizeof(d_hex)); memset(z_hex, 0, sizeof(z_hex)); memset(msg_hex, 0, sizeof(msg_hex));
            memset(ek_ref, 0, sizeof(ek_ref)); memset(dk_ref, 0, sizeof(dk_ref)); 
            memset(ct_ref, 0, sizeof(ct_ref)); memset(ss_ref, 0, sizeof(ss_ref));
        }
        else if (strncmp(line, "d = ", 4) == 0) strcpy(d_hex, line + 4);
        else if (strncmp(line, "z = ", 4) == 0) strcpy(z_hex, line + 4);
        else if (strncmp(line, "msg = ", 6) == 0) strcpy(msg_hex, line + 6);
        else if (strncmp(line, "ek = ", 5) == 0) strcpy(ek_ref, line + 5);
        else if (strncmp(line, "dk = ", 5) == 0) strcpy(dk_ref, line + 5);
        else if (strncmp(line, "c = ", 4) == 0) strcpy(ct_ref, line + 4);
        else if (strncmp(line, "ct = ", 5) == 0) strcpy(ct_ref, line + 5);
        else if (strncmp(line, "ss = ", 5) == 0) {
            strcpy(ss_ref, line + 5);
            d_hex[strcspn(d_hex, "\r\n")] = 0; z_hex[strcspn(z_hex, "\r\n")] = 0; msg_hex[strcspn(msg_hex, "\r\n")] = 0;
            ek_ref[strcspn(ek_ref, "\r\n")] = 0; dk_ref[strcspn(dk_ref, "\r\n")] = 0; ct_ref[strcspn(ct_ref, "\r\n")] = 0; ss_ref[strcspn(ss_ref, "\r\n")] = 0;

            uint8_t rand_seed[64], msg_seed[32];

            /* --- KEYGEN TEST --- */
            if (strlen(ek_ref) && strlen(dk_ref)) {
                hex2bin(d_hex, rand_seed);
                hex2bin(z_hex, rand_seed + 32);

                MlKemKey* key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
                if (key != NULL && wc_MlKemKey_MakeKeyWithRandom(key, rand_seed, 64) == 0) {
                    uint8_t pk[3000], sk[4000];
                    wc_MlKemKey_EncodePublicKey(key, pk, pk_len);
                    wc_MlKemKey_EncodePrivateKey(key, sk, sk_len);

                    uint8_t ek_bin[3000], dk_bin[4000];
                    hex2bin(ek_ref, ek_bin); hex2bin(dk_ref, dk_bin);
                    if (memcmp(pk, ek_bin, pk_len) == 0 && memcmp(sk, dk_bin, sk_len) == 0) keygen_pass++;
                    else printf(" [!] KeyGen Mismatch at count %d\n", count);
                } else printf(" [!] KeyGen Function Failed at count %d\n", count);
                if (key) wc_MlKemKey_Free(key);
            }

            /* --- ENCAPSULATION TEST --- */
            if (strlen(msg_hex) && strlen(ek_ref)) {
                hex2bin(msg_hex, msg_seed);
                
                MlKemKey* key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
                uint8_t ek_bin[3000]; hex2bin(ek_ref, ek_bin);
                wc_MlKemKey_DecodePublicKey(key, ek_bin, pk_len);

                uint8_t ct[3000], ss[32];
                if (wc_MlKemKey_EncapsulateWithRandom(key, ct, ss, msg_seed, 32) == 0) {
                    uint8_t ct_bin[3000], ss_bin[32];
                    hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);
                    if (memcmp(ct, ct_bin, ct_len) == 0 && memcmp(ss, ss_bin, 32) == 0) encap_pass++;
                    else printf(" [!] Encap Mismatch at count %d\n", count);
                } else printf(" [!] Encap Function Failed at count %d\n", count);
                if (key) wc_MlKemKey_Free(key);
            }

            /* --- DECAPSULATION TEST --- */
            if (strlen(dk_ref) && strlen(ct_ref) && strlen(ss_ref) && !strlen(msg_hex)) {
                MlKemKey* key = wc_MlKemKey_New(type, NULL, INVALID_DEVID);
                uint8_t dk_bin[4000]; hex2bin(dk_ref, dk_bin);
                wc_MlKemKey_DecodePrivateKey(key, dk_bin, sk_len);

                uint8_t ct_bin[3000], ss_bin[32];
                hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);
                
                uint8_t ss_out[32];
                // Standard decapsulate doesn't require random
                if (wc_MlKemKey_Decapsulate(key, ss_out, ct_bin, ct_len) == 0) {
                    if (memcmp(ss_out, ss_bin, 32) == 0) decap_pass++;
                    else printf(" [!] Decap Mismatch at count %d\n", count);
                } else printf(" [!] Decap Function Failed at count %d\n", count);
                if (key) wc_MlKemKey_Free(key);
            }
        }
    }
    fclose(fp);

    printf("\n  Summary for WolfSSL ML-KEM-%d\n", bits);
    if (keygen_pass > 0) printf("  KeyGen Passed:         %d\n", keygen_pass);
    if (encap_pass > 0)  printf("  Encapsulation Passed:  %d\n", encap_pass);
    if (decap_pass > 0)  printf("  Decapsulation Passed:  %d\n", decap_pass);
    printf("========================================================\n\n");
    return 0;
}
