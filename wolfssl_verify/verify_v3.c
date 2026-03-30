/*
 * verify_v3.c — wolfssl 5.8.4 ML-KEM NIST vector verifier
 *
 * API signatures taken directly from wolfssl 5.8.4 mlkem.h:
 *   wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId)
 *   wc_MlKemKey_DecodePublicKey(MlKemKey* key, const byte* in, word32 inSz)
 *   wc_MlKemKey_EncodePublicKey(MlKemKey* key, byte* out, word32 len)   <- len by value
 *   wc_MlKemKey_DecodePrivateKey(MlKemKey* key, const byte* in, word32 inSz)
 *   wc_MlKemKey_EncodePrivateKey(MlKemKey* key, byte* out, word32 len)  <- len by value
 *   wc_MlKemKey_Decapsulate(MlKemKey* key, byte* ss, const byte* ct, word32 ctSz)
 *   wc_MlKemKey_Free(MlKemKey* key)
 *
 * Type constants from wc_mlkem.h: WC_ML_KEM_512, WC_ML_KEM_768, WC_ML_KEM_1024
 *
 * Usage: ./verify <512|768|1024> <vectors.rsp>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* Include order matters for wolfssl */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>   /* WC_ML_KEM_512 etc. */
#include <wolfssl/wolfcrypt/mlkem.h>      /* MlKemKey, wc_MlKemKey_* */

/* ---- hex helpers ---- */
static int hexdig(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static int hex2bin(const char *hex, uint8_t *out, size_t maxlen) {
    size_t hlen = strlen(hex);
    if (hlen&1 || hlen/2>maxlen) return -1;
    for (size_t i=0; i<hlen/2; i++) {
        int hi=hexdig(hex[2*i]), lo=hexdig(hex[2*i+1]);
        if (hi<0||lo<0) return -1;
        out[i]=(uint8_t)((hi<<4)|lo);
    }
    return (int)(hlen/2);
}

/* ---- vector record ---- */
#define MAXHEX (3200*2+4)
typedef struct { int count; char ek[MAXHEX],dk[MAXHEX],ct[MAXHEX],ss[MAXHEX]; } Vec;

static int next_vec(FILE *fp, Vec *v) {
    char line[MAXHEX+32];
    memset(v,0,sizeof(*v)); v->count=-1;
    int found=0;
    while (fgets(line,sizeof(line),fp)) {
        char *p=line+strlen(line)-1;
        while(p>=line&&(*p=='\n'||*p=='\r'||*p==' ')) *p--='\0';
        if (!line[0]||line[0]=='#') continue;
        char *eq=strchr(line,'='); if (!eq) continue;
        *eq='\0';
        char *key=line, *val=eq+1;
        while(*key==' ') key++;
        p=key+strlen(key)-1; while(p>=key&&*p==' ') *p--='\0';
        while(*val==' ') val++;
        for(char*q=key;*q;q++) *q=(char)tolower((unsigned char)*q);
        if      (!strcmp(key,"count"))                   { v->count=atoi(val); found=1; }
        else if (!strcmp(key,"ek")||!strcmp(key,"pk"))   strncpy(v->ek,val,MAXHEX-1);
        else if (!strcmp(key,"dk")||!strcmp(key,"sk"))   strncpy(v->dk,val,MAXHEX-1);
        else if (!strcmp(key,"ct"))                      strncpy(v->ct,val,MAXHEX-1);
        else if (!strcmp(key,"ss"))                      strncpy(v->ss,val,MAXHEX-1);
        if (found&&v->ek[0]&&v->dk[0]&&v->ct[0]&&v->ss[0]) return 1;
    }
    return (found&&v->ek[0]&&v->dk[0]&&v->ct[0]&&v->ss[0])?1:0;
}

int main(int argc, char **argv) {
    if (argc<3) { fprintf(stderr,"Usage: %s <512|768|1024> <vectors.rsp>\n",argv[0]); return 1; }
    int bits=atoi(argv[1]);
    int type=(bits==512)?WC_ML_KEM_512:(bits==768)?WC_ML_KEM_768:WC_ML_KEM_1024;

    size_t ek_len=(bits==512)? 800:(bits==768)?1184:1568;
    size_t dk_len=(bits==512)?1632:(bits==768)?2400:3168;
    size_t ct_len=(bits==512)? 768:(bits==768)?1088:1568;
    size_t ss_len=32;

    uint8_t *ek_ref=malloc(ek_len), *dk_ref=malloc(dk_len);
    uint8_t *ct_ref=malloc(ct_len), *ss_ref=malloc(ss_len);
    uint8_t *ek_got=malloc(ek_len), *dk_got=malloc(dk_len), *ss_got=malloc(ss_len);

    FILE *fp=fopen(argv[2],"r");
    if (!fp) { perror(argv[2]); return 1; }

    wolfCrypt_Init();

    printf("\nML-KEM-%d — NIST vector verification (wolfssl 5.8.4)\n\n", bits);
    printf("%-6s  %-8s %-8s  %-10s\n","count","ek","dk","decaps(ss)");
    printf("──────  ──────── ────────  ──────────\n");

    int kg_pass=0, kg_fail=0, dec_pass=0, dec_fail=0;
    Vec v;

    while (next_vec(fp,&v)) {
        int c=v.count;
        int ek_rlen=hex2bin(v.ek,ek_ref,ek_len);
        int dk_rlen=hex2bin(v.dk,dk_ref,dk_len);
        int ct_rlen=hex2bin(v.ct,ct_ref,ct_len);
        int ss_rlen=hex2bin(v.ss,ss_ref,ss_len);
        if (ek_rlen<0||dk_rlen<0||ct_rlen<0||ss_rlen<0) {
            printf("%5d   [parse error]\n",c); continue;
        }

        /* ---- KEYGEN: ek round-trip (import NIST ek → export → compare) ---- */
        int ek_ok=0;
        {
            MlKemKey key;
            wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
            int rc = wc_MlKemKey_DecodePublicKey(&key, ek_ref, (word32)ek_rlen);
            if (rc==0) {
                rc = wc_MlKemKey_EncodePublicKey(&key, ek_got, (word32)ek_len);
                if (rc==0) ek_ok=(memcmp(ek_ref,ek_got,ek_len)==0);
            }
            if (!ek_ok && c==0) {
                fprintf(stderr,"  [ek #0] ref: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",ek_ref[i]);
                fprintf(stderr," got: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",ek_got[i]);
                fprintf(stderr," rc=%d\n",rc);
            }
            wc_MlKemKey_Free(&key);
        }

        /* ---- KEYGEN: dk round-trip ---- */
        int dk_ok=0;
        {
            MlKemKey key;
            wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
            int rc = wc_MlKemKey_DecodePrivateKey(&key, dk_ref, (word32)dk_rlen);
            if (rc==0) {
                rc = wc_MlKemKey_EncodePrivateKey(&key, dk_got, (word32)dk_len);
                if (rc==0) dk_ok=(memcmp(dk_ref,dk_got,dk_len)==0);
            }
            if (!dk_ok && c==0) {
                fprintf(stderr,"  [dk #0] ref: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",dk_ref[i]);
                fprintf(stderr," got: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",dk_got[i]);
                fprintf(stderr," rc=%d\n",rc);
            }
            wc_MlKemKey_Free(&key);
        }
        if (ek_ok&&dk_ok) kg_pass++; else kg_fail++;

        /* ---- DECAPS: NIST dk + NIST ct → compare ss ---- */
        int dec_ok=0;
        {
            MlKemKey key;
            wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
            int rc = wc_MlKemKey_DecodePrivateKey(&key, dk_ref, (word32)dk_rlen);
            if (rc==0) {
                rc = wc_MlKemKey_Decapsulate(&key, ss_got, ct_ref, (word32)ct_rlen);
                if (rc==0) dec_ok=(memcmp(ss_ref,ss_got,ss_len)==0);
            }
            if (!dec_ok && c==0) {
                fprintf(stderr,"  [dec #0] ref: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",ss_ref[i]);
                fprintf(stderr," got: ");
                for(int i=0;i<8;i++) fprintf(stderr,"%02x",ss_got[i]);
                fprintf(stderr," rc=%d\n",rc);
            }
            wc_MlKemKey_Free(&key);
        }
        if (dec_ok) dec_pass++; else dec_fail++;

        printf("%5d   %-8s %-8s  %-10s\n", c,
               ek_ok?"OK":"FAIL", dk_ok?"OK":"FAIL",
               dec_ok?"OK":"FAIL");
    }
    fclose(fp);

    int total=kg_pass+kg_fail;
    printf("\n──────  ──────── ────────  ──────────\n");
    printf("PASS    %2d/%-3d  %2d/%-3d   %2d/%d\n",
           kg_pass,total, kg_pass,total, dec_pass,dec_pass+dec_fail);
    int total_fail=kg_fail+dec_fail;
    printf("\n%s  (keygen_fail=%d  decaps_fail=%d)\n",
           total_fail?"OVERALL: FAIL":"OVERALL: PASS", kg_fail, dec_fail);

    free(ek_ref);free(dk_ref);free(ct_ref);free(ss_ref);
    free(ek_got);free(dk_got);free(ss_got);
    wolfCrypt_Cleanup();
    return total_fail?1:0;
}
