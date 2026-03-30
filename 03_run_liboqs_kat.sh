#!/usr/bin/env bash
set -euo pipefail
KAT_BIN="$HOME/liboqs/build/tests/kat_kem"
KAT_OUT="$HOME/liboqs/tests/KATs/kem"
EVAL_DIR="$HOME/pqc-kat-eval"
echo "======================================================"
echo " liboqs — ML-KEM KAT Generation"
echo "======================================================"
[ -x "$KAT_BIN" ] || { echo "ERROR: $KAT_BIN not found"; exit 1; }
mkdir -p "$KAT_OUT"
declare -A MAP=( ["ML-KEM-512"]="ml_kem_512" ["ML-KEM-768"]="ml_kem_768" ["ML-KEM-1024"]="ml_kem_1024" )
declare -A DIR=( ["ML-KEM-512"]="mlkem512"   ["ML-KEM-768"]="mlkem768"   ["ML-KEM-1024"]="mlkem1024"   )
cd "$HOME/liboqs/build/tests"
for VARIANT in "ML-KEM-512" "ML-KEM-768" "ML-KEM-1024"; do
    LNAME="${MAP[$VARIANT]}"
    DESTDIR="$EVAL_DIR/vectors/${DIR[$VARIANT]}"
    DEST="$DESTDIR/liboqs_${DIR[$VARIANT]}.rsp"
    mkdir -p "$DESTDIR"
    echo "  Running kat_kem $VARIANT..."
    "$KAT_BIN" "$VARIANT" 2>/dev/null || true
    # liboqs writes to KATs/kem/ relative to repo root
    RSP="$KAT_OUT/kat_kem_${LNAME}.rsp"
    if [ ! -f "$RSP" ]; then
        # also check build/tests/
        RSP2=$(find "$HOME/liboqs" -name "kat_kem_${LNAME}.rsp" 2>/dev/null | head -1)
        [ -n "$RSP2" ] && RSP="$RSP2"
    fi
    if [ -f "$RSP" ]; then
        cp "$RSP" "$DEST"
        echo "  OK: $(grep -c '^count' "$DEST") vectors -> $DEST"
    else
        echo "  WARN: no .rsp found for $VARIANT"
        echo "        Searched: $KAT_OUT/kat_kem_${LNAME}.rsp"
    fi
done
echo ""
echo "liboqs done."
echo "======================================================"
