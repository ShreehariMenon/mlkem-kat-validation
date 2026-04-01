#!/usr/bin/env bash
set -euo pipefail
EVAL_DIR="$HOME/pqc-kat-eval"
VECTORS_DIR="$EVAL_DIR/vectors"
echo "======================================================"
echo " ML-KEM KAT Evaluation — Setup"
echo "======================================================"
echo "[1/3] Creating vector subdirectories..."
mkdir -p "$VECTORS_DIR"/{mlkem512,mlkem768,mlkem1024}
mkdir -p "$EVAL_DIR/results"
echo "[2/3] Copying AWS-LC embedded KAT vectors..."
AWSLC_KAT="$HOME/aws-lc/crypto/fipsmodule/ml_kem/kat"
if [ -f "$AWSLC_KAT/mlkem512.txt" ]; then
    cp "$AWSLC_KAT/mlkem512.txt"  "$VECTORS_DIR/mlkem512/awslc_mlkem512.txt"
    cp "$AWSLC_KAT/mlkem768.txt"  "$VECTORS_DIR/mlkem768/awslc_mlkem768.txt"
    cp "$AWSLC_KAT/mlkem1024.txt" "$VECTORS_DIR/mlkem1024/awslc_mlkem1024.txt"
    echo "      OK: AWS-LC vectors copied"
else
    echo "      WARN: $AWSLC_KAT not found"
fi
echo "[3/3] Checking Python..."
python3 --version
echo ""
echo "Setup complete. Run scripts 01 through 05 in order."
echo "======================================================"
