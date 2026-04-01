#!/usr/bin/env bash
set -euo pipefail
KAT_SRC="$HOME/aws-lc/crypto/fipsmodule/ml_kem/kat"
EVAL_DIR="$HOME/pqc-kat-eval"
echo "======================================================"
echo " AWS-LC — KAT Vector Conversion"
echo "======================================================"
for VARIANT in mlkem512 mlkem768 mlkem1024; do
    SRC="$KAT_SRC/${VARIANT}.txt"
    DEST="$EVAL_DIR/vectors/$VARIANT/awslc_${VARIANT}.rsp"
    mkdir -p "$EVAL_DIR/vectors/$VARIANT"
    [ -f "$SRC" ] || { echo "  WARN: $SRC not found"; continue; }
    python3 - "$SRC" "$DEST" << 'PYEOF'
import sys
src, dest = sys.argv[1], sys.argv[2]
with open(src) as f: lines = f.read().strip().split('\n')
recs, cur, count = [], {}, 0
for ln in lines:
    ln = ln.strip()
    if not ln:
        if cur: cur['count']=count; recs.append(cur); cur={}; count+=1
        continue
    if '=' in ln:
        k,_,v = ln.partition('=')
        cur[k.strip().lower().replace(' ','')] = v.strip()
if cur: cur['count']=count; recs.append(cur)
with open(dest,'w') as f:
    bits = src.split('mlkem')[1].split('.')[0]
    f.write(f"# ML-KEM-{bits} (AWS-LC FIPS 203 vectors)\n\n")
    for r in recs:
        f.write(f"count = {r.get('count',0)}\n")
        f.write(f"seed = {r.get('keypaircoins',r.get('seed',''))}\n")
        for field in ('pk','sk','ct','ss'):
            if field in r: f.write(f"{field} = {r[field]}\n")
        f.write("\n")
print(f"  {src.split('/')[-1]}: {len(recs)} vectors -> {dest}")
PYEOF
done
echo ""
echo "AWS-LC done."
echo "======================================================"
