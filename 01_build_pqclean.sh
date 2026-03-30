#!/usr/bin/env bash
set -euo pipefail
PQCLEAN="$HOME/PQClean"
EVAL_DIR="$HOME/pqc-kat-eval"
echo "======================================================"
echo " PQClean — Build & KAT Generation"
echo "======================================================"
declare -A SCHEME_DIR=( [mlkem512]="ml-kem-512" [mlkem768]="ml-kem-768" [mlkem1024]="ml-kem-1024" )
for VARIANT in mlkem512 mlkem768 mlkem1024; do
    SCHEME="${SCHEME_DIR[$VARIANT]}"
    SDIR="$PQCLEAN/crypto_kem/$SCHEME/clean"
    OUTDIR="$EVAL_DIR/vectors/$VARIANT"
    mkdir -p "$OUTDIR"
    echo ""
    echo "--- $SCHEME ---"
    if [ ! -d "$SDIR" ]; then echo "  SKIP: $SDIR not found"; continue; fi
    WDIR=$(mktemp -d)
    trap "rm -rf $WDIR" EXIT
    cat > "$WDIR/katgen.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "randombytes.h"
static void phex(FILE*fp,const char*l,const uint8_t*d,size_t n){
    fprintf(fp,"%s = ",l);
    for(size_t i=0;i<n;i++)fprintf(fp,"%02x",d[i]);
    fprintf(fp,"\n");
}
int main(void){
    uint8_t entropy[48],seed[48];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES],ss[CRYPTO_BYTES],ss2[CRYPTO_BYTES];
    for(int i=0;i<48;i++)entropy[i]=(uint8_t)i;
    randombytes_init(entropy,NULL,256);
    char fname[64]; snprintf(fname,64,"pqclean_%s.rsp",CRYPTO_ALGNAME);
    for(char*p=fname;*p;p++)if(*p==' ')(*p)='_';
    FILE*fp=fopen(fname,"w"); if(!fp){perror("fopen");return 1;}
    fprintf(fp,"# %s (PQClean)\n\n",CRYPTO_ALGNAME);
    int fail=0;
    for(int c=0;c<100;c++){
        randombytes(seed,48);
        randombytes_init(seed,NULL,256);
        fprintf(fp,"count = %d\n",c);
        phex(fp,"seed",seed,48);
        if(crypto_kem_keypair(pk,sk)){fprintf(stderr,"keypair fail %d\n",c);fail++;continue;}
        phex(fp,"pk",pk,CRYPTO_PUBLICKEYBYTES);
        phex(fp,"sk",sk,CRYPTO_SECRETKEYBYTES);
        if(crypto_kem_enc(ct,ss,pk)){fprintf(stderr,"enc fail %d\n",c);fail++;continue;}
        phex(fp,"ct",ct,CRYPTO_CIPHERTEXTBYTES);
        phex(fp,"ss",ss,CRYPTO_BYTES);
        if(crypto_kem_dec(ss2,ct,sk)||memcmp(ss,ss2,CRYPTO_BYTES)){
            fprintf(stderr,"dec/mismatch %d\n",c);fail++;continue;}
        fprintf(fp,"\n");
    }
    fclose(fp);
    fprintf(stderr,"[PQClean %s] %d failures\n",CRYPTO_ALGNAME,fail);
    return fail?1:0;
}
CEOF
    COMMON_SRCS="$PQCLEAN/common/randombytes.c $PQCLEAN/common/fips202.c $PQCLEAN/common/sha2.c $PQCLEAN/common/aes.c"
    SCHEME_SRCS=$(find "$SDIR" -name "*.c" | tr '\n' ' ')
    gcc -O2 -I"$PQCLEAN/common" -I"$SDIR" \
        "$WDIR/katgen.c" $SCHEME_SRCS $COMMON_SRCS \
        -o "$WDIR/katgen" 2>&1 || { echo "  COMPILE FAILED"; continue; }
    cd "$WDIR" && ./katgen 2>&1
    RSP=$(find "$WDIR" -name "*.rsp" | head -1)
    if [ -n "$RSP" ]; then
        cp "$RSP" "$OUTDIR/pqclean_${VARIANT}.rsp"
        echo "  OK -> $OUTDIR/pqclean_${VARIANT}.rsp ($(grep -c '^count' "$OUTDIR/pqclean_${VARIANT}.rsp") vectors)"
    else
        echo "  WARN: no .rsp generated"
    fi
    cd "$EVAL_DIR"
done
echo ""
echo "PQClean done."
echo "======================================================"
