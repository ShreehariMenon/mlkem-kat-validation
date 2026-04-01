# ML-KEM FIPS 203 KAT Validation Framework

A pristine, high-performance, purely **native-C testing framework** designed to validate cryptographic libraries strictly against the deterministic official NIST Known Answer Tests (KAT) for the ML-KEM standard (FIPS 203).

## The Cryptography Challenge
Validating real-world cryptography libraries against official NIST algorithms requires more than simply checking if "Key A decrypts Ciphertext B". The NIST ACVP KATs demand that given a specific fixed random seed (a precise combination of exactly 64-bytes containing parameters `d` and `z`), a library mathematically **must** output an exact pre-determined Public Key (ek) and Secret Key (dk). 

Because high-level languages like Python and native high-level library bindings automatically utilize secure OS-level entropy (like `/dev/urandom`) by default, they completely fail these strict deterministic validation checks.

### The Solution: Native C Harnesses
This repository avoids multi-language guessing by utilizing pure, standalone C test harnesses. 

By executing natively in C, we are able to mathematically hook directly into the core Random Bytes Generators (e.g. WolfSSL's `WC_RNG` and AWS-LC's `RAND_METHOD`). The testing harnesses safely overwrite these memory blocks to seamlessly inject the NIST ACVP vectors, fully resolving exactly how these complex C structures behave in deterministic settings, completely circumventing standard OS-entropy overrides.

## Supported Libraries
* **WolfSSL** (`test_wolfssl_nist.c`)
* **AWS-LC / BoringSSL** (`test_awslc_nist.c`)
* **PQClean** (`test_pqclean_nist.c`)

*(Currently configured for testing variants ML-KEM-512, ML-KEM-768, and ML-KEM-1024)*

## Prerequisites
To compile and execute the test harnesses natively, your environment (e.g., WSL, Ubuntu, Native Linux) should have the libraries pre-built. The `Makefile` relies on the following standard locations:
* `~/wolfssl`
* `~/aws-lc`

If your libraries are located elsewhere, simply update the paths inside the `Makefile`.

## Quick Start Guide

### 1. Compile the Harnesses
Ensure you are in the repository directory and simply run:
```bash
make
```
*This command intelligently links your system libraries (`libwolfssl`, `libcrypto`) to the compiled testing binaries.*

### 2. Run the KAT Evaluation Suite
Execute the testing orchestrator script:
```bash
./run_kats.sh
```

### 3. Review the Results
The `run_kats.sh` script executes the compiled C-binaries silently and aggregates all the output checks across every sequence. You can cleanly review your detailed cryptographic accuracy logs generated instantly inside:

👉 `KAT_EVALUATION_REPORT.md`
