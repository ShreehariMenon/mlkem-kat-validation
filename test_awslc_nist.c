#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/err.h>

static uint8_t injected_d[32];
static uint8_t injected_z[32];
static uint8_t injected_m[32];

static int current_mode = 0; // 1 = keygen, 2 = encap

// Correct AWS-LC RAND_METHOD signature takes size_t
int custom_rand_bytes(uint8_t *buf, size_t num) {
    if (current_mode == 1 && num == 64) {
        memcpy(buf, injected_d, 32);
        memcpy(buf + 32, injected_z, 32);
        return 1;
    }
    if (current_mode == 2 && num == 32) {
        memcpy(buf, injected_m, 32);
        return 1;
    }
    return 1; 
}

static RAND_METHOD custom_rand = {
    NULL,
    custom_rand_bytes,
    NULL,
    NULL,
    custom_rand_bytes,
    NULL
};

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

// Helper to reliably map strings to NID without compiler MACRO failures
int get_mlkem_nid(int bits) {
    int nid = NID_undef;
    if (bits == 512) {
        nid = OBJ_sn2nid("MLKEM512");
        if (nid == NID_undef) nid = OBJ_sn2nid("kyber512");
    } else if (bits == 768) {
        nid = OBJ_sn2nid("MLKEM768");
        if (nid == NID_undef) nid = OBJ_sn2nid("kyber768");
    } else if (bits == 1024) {
        nid = OBJ_sn2nid("MLKEM1024");
        if (nid == NID_undef) nid = OBJ_sn2nid("kyber1024");
    }
    return nid;
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;

    int bits = atoi(argv[1]);
    int alg_nid = get_mlkem_nid(bits);

    FILE *fp = fopen(argv[2], "r");
    if (!fp) return 1;

    char line[10000];
    char d_hex[100]="", z_hex[100]="", msg_hex[100]="";
    char ek_ref[10000]="", dk_ref[10000]="", ct_ref[10000]="", ss_ref[10000]="";
    
    int count = -1, keygen_pass = 0, encap_pass = 0, decap_pass = 0;

    RAND_set_rand_method(&custom_rand);

    printf("========================================================\n");
    printf("  AWS-LC ML-KEM-%d KAT Verification                     \n", bits);
    if (alg_nid == NID_undef) {
        printf("  [ERROR] ML-KEM-%d unsupported. NID not found.           \n", bits);
    }
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
        else if (strncmp(line, "m = ", 4) == 0) strcpy(msg_hex, line + 4);
        else if (strncmp(line, "ek = ", 5) == 0) strcpy(ek_ref, line + 5);
        else if (strncmp(line, "dk = ", 5) == 0) strcpy(dk_ref, line + 5);
        else if (strncmp(line, "c = ", 4) == 0) strcpy(ct_ref, line + 4);
        else if (strncmp(line, "ct = ", 5) == 0) strcpy(ct_ref, line + 5);
        else if (strncmp(line, "ss = ", 5) == 0) strcpy(ss_ref, line + 5);
        
        if (line[0] == '\n' || line[0] == '\r') {
            if (count == -1) continue;
            
            d_hex[strcspn(d_hex, "\r\n")] = 0; z_hex[strcspn(z_hex, "\r\n")] = 0; msg_hex[strcspn(msg_hex, "\r\n")] = 0;
            ek_ref[strcspn(ek_ref, "\r\n")] = 0; dk_ref[strcspn(dk_ref, "\r\n")] = 0; ct_ref[strcspn(ct_ref, "\r\n")] = 0; ss_ref[strcspn(ss_ref, "\r\n")] = 0;

            hex2bin(d_hex, injected_d); 
            hex2bin(z_hex, injected_z);
            if (strlen(msg_hex)) hex2bin(msg_hex, injected_m);

            if (alg_nid == NID_undef) continue;

            if (strlen(d_hex) && strlen(z_hex) && strlen(ek_ref) && strlen(dk_ref)) {
                current_mode = 1;

                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(alg_nid, NULL);
                EVP_PKEY *pkey = NULL;
                
                if (ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1) {
                    size_t pk_len = 0, sk_len = 0;
                    EVP_PKEY_get_raw_public_key(pkey, NULL, &pk_len);
                    EVP_PKEY_get_raw_private_key(pkey, NULL, &sk_len);
                    
                    uint8_t pk[3000], sk[4000];
                    EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len);
                    EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len);

                    uint8_t ek_bin[3000], dk_bin[4000];
                    hex2bin(ek_ref, ek_bin); hex2bin(dk_ref, dk_bin);
                    
                    if (memcmp(pk, ek_bin, pk_len) == 0 && memcmp(sk, dk_bin, sk_len) == 0) keygen_pass++;
                    else printf(" [!] KeyGen Mismatch at count %d\n", count);
                } else {
                    printf(" [!] KeyGen Function Failed at count %d (ctx=%p)\n", count, (void*)ctx);
                    ERR_print_errors_fp(stderr);
                }
                
                if (pkey) EVP_PKEY_free(pkey);
                if (ctx) EVP_PKEY_CTX_free(ctx);
            }

            if (strlen(msg_hex) && strlen(ek_ref) && strlen(ct_ref) && strlen(ss_ref)) {
                current_mode = 2;
                uint8_t ek_bin[3000]; size_t ek_len = hex2bin(ek_ref, ek_bin);
                EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(alg_nid, NULL, ek_bin, ek_len);
                
                if (pkey) {
                    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
                    if (pctx) {
                        uint8_t ct[3000], ss[32];
                        size_t ct_len = 3000, ss_len = 32;
                        
                        if (EVP_PKEY_encapsulate(pctx, ct, &ct_len, ss, &ss_len) == 1) {
                            uint8_t ct_bin[3000], ss_bin[32];
                            hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);
                            if (memcmp(ct, ct_bin, ct_len) == 0 && memcmp(ss, ss_bin, 32) == 0) encap_pass++;
                            else printf(" [!] Encap Mismatch at count %d\n", count);
                        } else {
                            printf(" [!] Encap Failed at count %d\n", count);
                            ERR_print_errors_fp(stderr);
                        }
                    } else printf(" [!] Encap CTX Failed\n");
                    if (pctx) EVP_PKEY_CTX_free(pctx);
                } else {
                    printf(" [!] EVP_PKEY_new_raw_public_key failed at count %d (nid=%d, len=%zu)\n", count, alg_nid, ek_len);
                    ERR_print_errors_fp(stderr);
                }
                if (pkey) EVP_PKEY_free(pkey);
            }

            if (strlen(dk_ref) && strlen(ct_ref) && strlen(ss_ref) && !strlen(msg_hex)) {
                uint8_t dk_bin[4000]; size_t sk_len = hex2bin(dk_ref, dk_bin);
                EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(alg_nid, NULL, dk_bin, sk_len);
                
                if (pkey) {
                    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
                    if (ctx) {
                        uint8_t ct_bin[3000], ss_bin[32];
                        size_t ct_len = hex2bin(ct_ref, ct_bin); hex2bin(ss_ref, ss_bin);
                        
                        uint8_t ss_out[32]; size_t ss_out_len = 32;
                        if (EVP_PKEY_decapsulate(ctx, ss_out, &ss_out_len, ct_bin, ct_len) == 1) {
                            if (memcmp(ss_out, ss_bin, 32) == 0) decap_pass++;
                            else printf(" [!] Decap Mismatch at count %d\n", count);
                        } 
                    }
                    if (ctx) EVP_PKEY_CTX_free(ctx);
                }
                if (pkey) EVP_PKEY_free(pkey);
            }
            
            memset(d_hex, 0, sizeof(d_hex)); memset(z_hex, 0, sizeof(z_hex)); memset(msg_hex, 0, sizeof(msg_hex));
            memset(ek_ref, 0, sizeof(ek_ref)); memset(dk_ref, 0, sizeof(dk_ref)); 
            memset(ct_ref, 0, sizeof(ct_ref)); memset(ss_ref, 0, sizeof(ss_ref));
            count = -1;
        }
    }
    fclose(fp);

    if (alg_nid != NID_undef) {
        printf("\n  Summary for AWS-LC ML-KEM-%d\n", bits);
        if (keygen_pass > 0) printf("  KeyGen Passed:         %d\n", keygen_pass);
        if (encap_pass > 0)  printf("  Encapsulation Passed:  %d\n", encap_pass);
        if (decap_pass > 0)  printf("  Decapsulation Passed:  %d\n", decap_pass);
        printf("========================================================\n\n");
    }
    return 0;
}
