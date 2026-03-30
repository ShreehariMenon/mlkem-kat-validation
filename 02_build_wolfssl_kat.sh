#!/usr/bin/env bash
set -euo pipefail
WOLFSSL="$HOME/wolfssl"
EVAL_DIR="$HOME/pqc-kat-eval"
WDIR="$EVAL_DIR/wolfssl"
mkdir -p "$WDIR"
echo "======================================================"
echo " wolfssl — ML-KEM KAT Harness"
echo "======================================================"
echo "[1/3] Writing KAT harness..."
cat > "$WDIR/wkat.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
typedef struct{uint8_t key[32];uint8_t v[16];}DRBG;
static DRBG G;
static void aes_ecb(uint8_t*key,uint8_t*in,uint8_t*out){
    Aes a; wc_AesSetKeyDirect(&a,key,32,NULL,AES_ENCRYPTION);
    wc_AesEncryptDirect(&a,out,in);}
static void drbg_update(uint8_t*data){
    uint8_t t[48];
    for(int i=0;i<3;i++){
        for(int j=15;j>=0;j--){if(G.v[j]==0xff)G.v[j]=0;else{G.v[j]++;break;}}
        aes_ecb(G.key,G.v,t+i*16);}
    if(data)for(int i=0;i<48;i++)t[i]^=data[i];
    memcpy(G.key,t,32);memcpy(G.v,t+32,16);}
static void drbg_init(uint8_t*seed){
    uint8_t s[48]; memcpy(s,seed,48);
    memset(G.key,0,32);memset(G.v,0,16);
    drbg_update(s);}
static void drbg_bytes(uint8_t*out,size_t n){
    uint8_t blk[16];
    while(n>0){
        for(int j=15;j>=0;j--){if(G.v[j]==0xff)G.v[j]=0;else{G.v[j]++;break;}}
        aes_ecb(G.key,G.v,blk);
        size_t take=n>16?16:n;
        memcpy(out,blk,take);out+=take;n-=take;}
    drbg_update(NULL);}
static void phex(const char*l,const uint8_t*d,size_t n){
    printf("%s = ",l);
    for(size_t i=0;i<n;i++)printf("%02x",d[i]);
    printf("\n");}
int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"Usage: %s <512|768|1024>\n",argv[0]);return 1;}
    int bits=atoi(argv[1]);
    int type=(bits==512)?MLKEM512:(bits==768)?MLKEM768:MLKEM1024;
    size_t pk_len=(bits==512)?800:(bits==768)?1184:1568;
    size_t sk_len=(bits==512)?1632:(bits==768)?2400:3168;
    size_t ct_len=(bits==512)?768:(bits==768)?1088:1568;
    size_t ss_len=32;
    uint8_t*pk=malloc(pk_len),*sk=malloc(sk_len);
    uint8_t*ct=malloc(ct_len),*ss=malloc(ss_len),*ss2=malloc(ss_len);
    uint8_t entropy[48],seed[48];
    wolfSSL_Init();
    for(int i=0;i<48;i++)entropy[i]=(uint8_t)i;
    drbg_init(entropy);
    printf("# ML-KEM-%d (wolfssl)\n\n",bits);
    int fail=0;
    for(int c=0;c<100;c++){
        drbg_bytes(seed,48); drbg_init(seed);
        printf("count = %d\n",c); phex("seed",seed,48);
        MlKemKey key; WC_RNG rng;
        wc_MlKemKey_Init(type,&key,NULL,INVALID_DEVID);
        wc_InitRng(&rng);
        if(wc_MlKemKey_MakeKeyWithRng(&key,&rng)){
            fprintf(stderr,"keygen fail %d\n",c);fail++;
            wc_MlKemKey_Free(&key);wc_FreeRng(&rng);continue;}
        word32 pl=pk_len,sl=sk_len;
        wc_MlKemKey_EncodePublicKey(&key,pk,&pl);
        wc_MlKemKey_EncodePrivateKey(&key,sk,&sl);
        phex("pk",pk,pk_len); phex("sk",sk,sk_len);
        if(wc_MlKemKey_Encapsulate(&key,ct,ss,&rng)){
            fprintf(stderr,"enc fail %d\n",c);fail++;
            wc_MlKemKey_Free(&key);wc_FreeRng(&rng);continue;}
        phex("ct",ct,ct_len); phex("ss",ss,ss_len);
        if(wc_MlKemKey_Decapsulate(&key,ss2,ct,ct_len)||
           memcmp(ss,ss2,ss_len)){
            fprintf(stderr,"dec/mismatch %d\n",c);fail++;}
        printf("\n");
        wc_MlKemKey_Free(&key); wc_FreeRng(&rng);}
    free(pk);free(sk);free(ct);free(ss);free(ss2);
    wolfSSL_Cleanup();
    fprintf(stderr,"wolfssl ML-KEM-%d: %d failures\n",bits,fail);
    return fail?1:0;}
CEOF
echo "[2/3] Compiling..."
gcc -O2 \
    -I"$WOLFSSL" -I"$WOLFSSL/wolfssl" \
    "$WDIR/wkat.c" \
    -L"$WOLFSSL/build" -lwolfssl \
    -Wl,-rpath,"$WOLFSSL/build" \
    -o "$WDIR/wkat" 2>&1 || {
        echo "  Compile failed. wolfssl may need --enable-kyber rebuild."
        echo "  See README.md for rebuild instructions."
        exit 1
    }
echo "  OK"
echo "[3/3] Running for 512 / 768 / 1024..."
for BITS in 512 768 1024; do
    OUT="$EVAL_DIR/vectors/mlkem${BITS}/wolfssl_mlkem${BITS}.rsp"
    LD_LIBRARY_PATH="$WOLFSSL/build:${LD_LIBRARY_PATH:-}" \
        "$WDIR/wkat" "$BITS" > "$OUT" 2>/tmp/wkat_err_${BITS}.txt && \
        echo "  ML-KEM-${BITS}: OK ($(grep -c '^count' "$OUT") vectors) -> $OUT" || \
        { echo "  ML-KEM-${BITS}: FAILED — $(cat /tmp/wkat_err_${BITS}.txt)"; }
done
echo ""
echo "wolfssl done."
echo "======================================================"
