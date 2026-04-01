# ML-KEM FIPS 203 KAT Evaluation Report
Generated on: Wednesday 01 April 2026 03:03:10 PM IST

## Objective
This framework executes exact NIST KAT ACVP verification against WolfSSL and AWS-LC using native C harnesses, directly intercepting the internal Deterministic Random Byte Generators (DRBGs).

### test_wolfssl_nist (512)
```text
========================================================
  WolfSSL ML-KEM-512 KAT Verification                    
========================================================

  Summary for WolfSSL ML-KEM-512
  KeyGen Passed:         25
  Encapsulation Passed:  25
========================================================

```

### test_wolfssl_nist (768)
```text
========================================================
  WolfSSL ML-KEM-768 KAT Verification                    
========================================================

  Summary for WolfSSL ML-KEM-768
  KeyGen Passed:         25
  Encapsulation Passed:  25
========================================================

```

### test_wolfssl_nist (1024)
```text
========================================================
  WolfSSL ML-KEM-1024 KAT Verification                    
========================================================

  Summary for WolfSSL ML-KEM-1024
  KeyGen Passed:         25
  Encapsulation Passed:  25
========================================================

```

### test_awslc_nist (512)
```text
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 988
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
105858463511712:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
========================================================
  AWS-LC ML-KEM-512 KAT Verification                     
========================================================
 [!] KeyGen Function Failed at count 1 (ctx=(nil))
 [!] KeyGen Function Failed at count 2 (ctx=(nil))
 [!] KeyGen Function Failed at count 3 (ctx=(nil))
 [!] KeyGen Function Failed at count 4 (ctx=(nil))
 [!] KeyGen Function Failed at count 5 (ctx=(nil))
 [!] KeyGen Function Failed at count 6 (ctx=(nil))
 [!] KeyGen Function Failed at count 7 (ctx=(nil))
 [!] KeyGen Function Failed at count 8 (ctx=(nil))
 [!] KeyGen Function Failed at count 9 (ctx=(nil))
 [!] KeyGen Function Failed at count 10 (ctx=(nil))
 [!] KeyGen Function Failed at count 11 (ctx=(nil))
 [!] KeyGen Function Failed at count 12 (ctx=(nil))
 [!] KeyGen Function Failed at count 13 (ctx=(nil))
 [!] KeyGen Function Failed at count 14 (ctx=(nil))
 [!] KeyGen Function Failed at count 15 (ctx=(nil))
 [!] KeyGen Function Failed at count 16 (ctx=(nil))
 [!] KeyGen Function Failed at count 17 (ctx=(nil))
 [!] KeyGen Function Failed at count 18 (ctx=(nil))
 [!] KeyGen Function Failed at count 19 (ctx=(nil))
 [!] KeyGen Function Failed at count 20 (ctx=(nil))
 [!] KeyGen Function Failed at count 21 (ctx=(nil))
 [!] KeyGen Function Failed at count 22 (ctx=(nil))
 [!] KeyGen Function Failed at count 23 (ctx=(nil))
 [!] KeyGen Function Failed at count 24 (ctx=(nil))
 [!] KeyGen Function Failed at count 25 (ctx=(nil))
 [!] EVP_PKEY_new_raw_public_key failed at count 1 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 2 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 3 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 4 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 5 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 6 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 7 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 8 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 9 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 10 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 11 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 12 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 13 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 14 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 15 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 16 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 17 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 18 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 19 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 20 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 21 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 22 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 23 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 24 (nid=988, len=800)
 [!] EVP_PKEY_new_raw_public_key failed at count 25 (nid=988, len=800)

  Summary for AWS-LC ML-KEM-512
========================================================

```

### test_awslc_nist (768)
```text
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 989
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
93875732042912:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
========================================================
  AWS-LC ML-KEM-768 KAT Verification                     
========================================================
 [!] KeyGen Function Failed at count 26 (ctx=(nil))
 [!] KeyGen Function Failed at count 27 (ctx=(nil))
 [!] KeyGen Function Failed at count 28 (ctx=(nil))
 [!] KeyGen Function Failed at count 29 (ctx=(nil))
 [!] KeyGen Function Failed at count 30 (ctx=(nil))
 [!] KeyGen Function Failed at count 31 (ctx=(nil))
 [!] KeyGen Function Failed at count 32 (ctx=(nil))
 [!] KeyGen Function Failed at count 33 (ctx=(nil))
 [!] KeyGen Function Failed at count 34 (ctx=(nil))
 [!] KeyGen Function Failed at count 35 (ctx=(nil))
 [!] KeyGen Function Failed at count 36 (ctx=(nil))
 [!] KeyGen Function Failed at count 37 (ctx=(nil))
 [!] KeyGen Function Failed at count 38 (ctx=(nil))
 [!] KeyGen Function Failed at count 39 (ctx=(nil))
 [!] KeyGen Function Failed at count 40 (ctx=(nil))
 [!] KeyGen Function Failed at count 41 (ctx=(nil))
 [!] KeyGen Function Failed at count 42 (ctx=(nil))
 [!] KeyGen Function Failed at count 43 (ctx=(nil))
 [!] KeyGen Function Failed at count 44 (ctx=(nil))
 [!] KeyGen Function Failed at count 45 (ctx=(nil))
 [!] KeyGen Function Failed at count 46 (ctx=(nil))
 [!] KeyGen Function Failed at count 47 (ctx=(nil))
 [!] KeyGen Function Failed at count 48 (ctx=(nil))
 [!] KeyGen Function Failed at count 49 (ctx=(nil))
 [!] KeyGen Function Failed at count 50 (ctx=(nil))
 [!] EVP_PKEY_new_raw_public_key failed at count 26 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 27 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 28 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 29 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 30 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 31 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 32 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 33 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 34 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 35 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 36 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 37 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 38 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 39 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 40 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 41 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 42 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 43 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 44 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 45 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 46 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 47 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 48 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 49 (nid=989, len=1184)
 [!] EVP_PKEY_new_raw_public_key failed at count 50 (nid=989, len=1184)

  Summary for AWS-LC ML-KEM-768
========================================================

```

### test_awslc_nist (1024)
```text
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp_ctx.c:65:algorithm 990
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
95031593796768:error:06000080:public key routines:OPENSSL_internal:UNSUPPORTED_ALGORITHM:/home/User/aws-lc/crypto/fipsmodule/evp/evp.c:578:
========================================================
  AWS-LC ML-KEM-1024 KAT Verification                     
========================================================
 [!] KeyGen Function Failed at count 51 (ctx=(nil))
 [!] KeyGen Function Failed at count 52 (ctx=(nil))
 [!] KeyGen Function Failed at count 53 (ctx=(nil))
 [!] KeyGen Function Failed at count 54 (ctx=(nil))
 [!] KeyGen Function Failed at count 55 (ctx=(nil))
 [!] KeyGen Function Failed at count 56 (ctx=(nil))
 [!] KeyGen Function Failed at count 57 (ctx=(nil))
 [!] KeyGen Function Failed at count 58 (ctx=(nil))
 [!] KeyGen Function Failed at count 59 (ctx=(nil))
 [!] KeyGen Function Failed at count 60 (ctx=(nil))
 [!] KeyGen Function Failed at count 61 (ctx=(nil))
 [!] KeyGen Function Failed at count 62 (ctx=(nil))
 [!] KeyGen Function Failed at count 63 (ctx=(nil))
 [!] KeyGen Function Failed at count 64 (ctx=(nil))
 [!] KeyGen Function Failed at count 65 (ctx=(nil))
 [!] KeyGen Function Failed at count 66 (ctx=(nil))
 [!] KeyGen Function Failed at count 67 (ctx=(nil))
 [!] KeyGen Function Failed at count 68 (ctx=(nil))
 [!] KeyGen Function Failed at count 69 (ctx=(nil))
 [!] KeyGen Function Failed at count 70 (ctx=(nil))
 [!] KeyGen Function Failed at count 71 (ctx=(nil))
 [!] KeyGen Function Failed at count 72 (ctx=(nil))
 [!] KeyGen Function Failed at count 73 (ctx=(nil))
 [!] KeyGen Function Failed at count 74 (ctx=(nil))
 [!] KeyGen Function Failed at count 75 (ctx=(nil))
 [!] EVP_PKEY_new_raw_public_key failed at count 51 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 52 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 53 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 54 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 55 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 56 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 57 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 58 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 59 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 60 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 61 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 62 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 63 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 64 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 65 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 66 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 67 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 68 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 69 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 70 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 71 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 72 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 73 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 74 (nid=990, len=1568)
 [!] EVP_PKEY_new_raw_public_key failed at count 75 (nid=990, len=1568)

  Summary for AWS-LC ML-KEM-1024
========================================================

```

### test_pqclean_nist (512)
**SKIPPED**: Binary not found. Please run `make test_pqclean_nist`.

