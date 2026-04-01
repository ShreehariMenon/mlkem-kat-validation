#!/usr/bin/env bash
set -e

echo "Ensuring NIST vectors are up to date and correctly formatted..."
python3 fetch_nist_vectors.py

# Setup Output Report
REPORT="KAT_EVALUATION_REPORT.md"
echo "# ML-KEM FIPS 203 KAT Evaluation Report" > "$REPORT"
echo "Generated on: $(date)" >> "$REPORT"
echo "" >> "$REPORT"
echo "## Objective" >> "$REPORT"
echo "This framework executes exact NIST KAT ACVP verification against WolfSSL and AWS-LC using native C harnesses, directly intercepting the internal Deterministic Random Byte Generators (DRBGs)." >> "$REPORT"
echo "" >> "$REPORT"

echo "=========================================================="
echo "  ML-KEM NIST KAT MASTER RUNNER                           "
echo "=========================================================="

run_test() {
    binary=$1
    variant=$2
    vector_file=$3

    if [ ! -f "$binary" ]; then
        echo "- [$binary] SKIPPED (Binary not compiled)"
        echo "### $binary ($variant)" >> "$REPORT"
        echo "**SKIPPED**: Binary not found. Please run \`make $binary\`." >> "$REPORT"
        echo "" >> "$REPORT"
        return
    fi
    
    if [ ! -f "$vector_file" ]; then
        echo "- [$binary] SKIPPED (Vector file $vector_file not found)"
        return
    fi

    echo "- Running $binary for $variant..."
    echo "### $binary ($variant)" >> "$REPORT"
    echo '```text' >> "$REPORT"
    # Execute and append output directly to the report
    LD_LIBRARY_PATH="$HOME/wolfssl/build:$HOME/aws-lc/build/crypto:${LD_LIBRARY_PATH:-}" \
    "./$binary" "$variant" "$vector_file" >> "$REPORT" 2>&1 || true
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
}

# 1. Test WolfSSL
echo "--- Testing WolfSSL ---"
run_test "test_wolfssl_nist" "512" "vectors/nist/mlkem512_acvp.rsp"
run_test "test_wolfssl_nist" "768" "vectors/nist/mlkem768_acvp.rsp"
run_test "test_wolfssl_nist" "1024" "vectors/nist/mlkem1024_acvp.rsp"

# 2. Test AWS-LC
echo "--- Testing AWS-LC ---"
run_test "test_awslc_nist" "512" "vectors/nist/mlkem512_acvp.rsp"
run_test "test_awslc_nist" "768" "vectors/nist/mlkem768_acvp.rsp"
run_test "test_awslc_nist" "1024" "vectors/nist/mlkem1024_acvp.rsp"

# 3. Test PQClean (if exists)
echo "--- Testing PQClean ---"
run_test "test_pqclean_nist" "512" "vectors/nist/mlkem512_acvp.rsp"

echo "=========================================================="
echo "DONE! Results have been aggregated into $REPORT"
echo "=========================================================="
