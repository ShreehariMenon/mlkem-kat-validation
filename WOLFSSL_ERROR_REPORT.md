# Formal Report: ML-KEM FIPS 203 KAT Verification (WolfSSL)

## Objective
The objective was to verify whether the `0%` match rate observed during WolfSSL's ML-KEM Key Generation test against Known Answer Test (KAT) inputs is caused by a bug in the **WolfSSL** cryptography library or an error in the **evaluation test harness**. A secondary objective was to correctly import the official NIST ACVP JSON test vectors to ensure verification runs directly against official FIPS-compliant inputs.

## Conclusion: It is a Test Script Error
The discrepancy is definitively caused by a logic error in your evaluation script (`02_build_wolfssl_kat.sh` / `wkat.c`), **not** a bug in WolfSSL. 

### Proof of the Error
In `wkat.c`, the script attempts to inject determinism into the Key Generation algorithm by initializing a custom AES block DRBG:

```c
        // 1. Generate deterministic seed from a custom AES-ECB DRBG
        drbg_bytes(seed, 48); 
        drbg_init(seed);
```

Immediately after generating this test seed, the script calls WolfSSL to generate the keys:
```c
        // 2. Initialize a generic WolfSSL Random Number Generator (WC_RNG)
        wc_MlKemKey_Init(type, &key, NULL, INVALID_DEVID);
        wc_InitRng(&rng);

        // 3. Generate ML-KEM Keys using the generic RNG, ignoring the seed
        if(wc_MlKemKey_MakeKeyWithRng(&key, &rng)){ ... }
```

**The fatal mistake:** `wc_InitRng(&rng)` defaults to initializing a non-deterministic RNG pulling entropy directly from the Operating System (e.g., `/dev/urandom` or Windows CryptGenRandom). It entirely ignores the `seed` generated on the preceding line. Since FIPS 203 Key Generation requires exactly 64 bytes of deterministic randomness (`d` and `z`), WolfSSL was generating completely random keys instead of the fixed deterministic keys required by the KAT framework. This results in an immediate 0% match against the official NIST outputs.

This error uniquely affects the WolfSSL script. Other libraries (like PQClean and LibOQS) use global RNG hooks (`randombytes`), which allowed those test harnesses to successfully intercept the entropy calls.

*Moreover, this fully explains why the separate `verify.c` test successfully achieves 100% on Encapsulation and Decapsulation: That script actually imports the NIST reference keys instead of attempting to generate them internally using the unseeded RNG!*

## Sourcing the Official NIST ACVP Test Vectors
The AWS-LC repository uses test vectors that were generated and validated via the ACVP framework, but to strictly test against official NIST inputs as requested, the vectors must be pulled directly from NIST.

We wrote a Python parser (`fetch_nist_vectors.py`) that successfully downloaded the **Final FIPS-203 ML-KEM Test Vectors** directly from the official NIST ACVP GitHub database:
- `ML-KEM-keyGen-FIPS203/prompt.json`
- `ML-KEM-keyGen-FIPS203/expectedResults.json`
- `ML-KEM-encapDecap-FIPS203/prompt.json`

The python script processed the split KeyGen and Encap JSONs and unified them into strict NIST `.rsp` format files locally in your workspace under `vectors/nist/`.

## Next Steps for the Guide / GitHub Report
This report serves as verification that **no Github Issue needs to be raised against WolfSSL**. Instead, the testing script must be refactored to override WolfSSL's internal `WC_RNG` with a mock function that supplies the explicit `d` and `z` inputs listed in the ACVP `.rsp` vectors. 

If raising this to a supervisor or guide, point out the source files in `wkat.c` lacking the explicit seed injection into the `WC_RNG` struct.
