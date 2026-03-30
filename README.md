# ML-KEM KAT Cross-Library Verification

## Overview

This project evaluates the correctness of ML-KEM (FIPS 203) implementations across multiple cryptographic libraries using Known Answer Tests (KATs).

## Libraries Tested

* liboqs
* PQClean
* AWS-LC
* wolfSSL

## Methodology

1. Generate KAT vectors for each library
2. Normalize outputs into `.rsp` format
3. Compare across libraries field-by-field:

   * Public Key (pk)
   * Secret Key (sk)
   * Ciphertext (ct)
   * Shared Secret (ss)

## Key Findings

* liboqs, PQClean, AWS-LC: 100% match with NIST-compatible outputs
* wolfSSL:

  * Key Generation: ❌ 0% match
  * Encapsulation: ✅ 100% match
  * Decapsulation: ✅ 100% match

## Root Cause Hypothesis

wolfSSL ML-KEM key generation likely diverges from FIPS 203 due to differences in private key construction (missing G(d||k) hash step).

## Reproducibility

Run:

```bash
./00_setup.sh
./01_build_pqclean.sh
./02_build_wolfssl_kat.sh
./03_run_liboqs_kat.sh
./04_run_awslc_kat.sh
python3 05_compare.py
```

## Output

* `results/mlkem_kat_comparison.txt`
* Detailed accuracy reports included

## Status

⚠️ Under investigation — potential wolfSSL deviation from FIPS 203
