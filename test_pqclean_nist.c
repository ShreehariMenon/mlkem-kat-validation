#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"

static uint8_t *injected_seed = NULL;
static size_t injected_len = 0;
static size_t injected_pos = 0;

void PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    if (injected_seed && injected_pos + outlen <= injected_len) {
        memcpy(out, injected_seed + injected_pos, outlen);
        injected_pos += outlen;
    } else {
        fprintf(stderr, "ERROR: randombytes requested %zu bytes, but only %zu available\n", outlen, injected_len - injected_pos);
        exit(1);
    }
}
int PQCLEAN_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) { return 0; }

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
    if(argc<2) { printf("Usage: %s <nist_kat.rsp>\n", argv[0]); return 1; }
    FILE *fp = fopen(argv[1], "r");
    if(!fp) { perror("fopen"); return 1; }
    
    char line[4096];
    char d_hex[100]="", z_hex[100]="", ek_ref[4096]="", dk_ref[4096]="";
    int count = -1;
    int pass=0, fail=0;
    
    printf("Testing PQClean against NIST KeyGen vectors...\n");
    while(fgets(line, sizeof(line), fp)) {
        if(strncmp(line, "count = ", 8) == 0) count = atoi(line+8);
        else if(strncmp(line, "d = ", 4) == 0) strcpy(d_hex, line+4);
        else if(strncmp(line, "z = ", 4) == 0) strcpy(z_hex, line+4);
        else if(strncmp(line, "ek = ", 5) == 0) strcpy(ek_ref, line+5);
        else if(strncmp(line, "dk = ", 5) == 0) {
            strcpy(dk_ref, line+5);
            d_hex[strcspn(d_hex, "\n")] = 0;
            z_hex[strcspn(z_hex, "\n")] = 0;
            ek_ref[strcspn(ek_ref, "\n")] = 0;
            dk_ref[strcspn(dk_ref, "\n")] = 0;
            
            uint8_t d[32], z[32], seed[64];
            hex2bin(d_hex, d); hex2bin(z_hex, z);
            memcpy(seed, d, 32); memcpy(seed+32, z, 32);
            
            injected_seed = seed;
            injected_len = 64;
            injected_pos = 0;
            
            uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES], sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
            if(PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) != 0) {
                printf("Keypair failed\n"); fail++; continue;
            }
            
            uint8_t ek_bin[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES]; hex2bin(ek_ref, ek_bin);
            uint8_t dk_bin[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES]; hex2bin(dk_ref, dk_bin);
            
            if(memcmp(pk, ek_bin, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES)==0 && memcmp(sk, dk_bin, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES)==0) {
                pass++;
            } else {
                printf("Mismatch at count %d\n", count); fail++;
            }
        }
    }
    fclose(fp);
    printf("PQClean KeyGen -> Pass: %d, Fail: %d\n", pass, fail);
    return fail;
}
