# ML-KEM FIPS 203 KAT Evaluation Report
Generated on: Wednesday 01 April 2026 05:35:38 PM IST

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
========================================================
  AWS-LC ML-KEM-512 Validation (vs NIST)
========================================================

Total Vectors: 50
Valid Vectors: 50
✔ All vectors valid

Accuracy: 100.00%
```

### test_awslc_nist (768)
```text
========================================================
  AWS-LC ML-KEM-768 Validation (vs NIST)
========================================================

Total Vectors: 50
Valid Vectors: 50
✔ All vectors valid

Accuracy: 100.00%
```

### test_awslc_nist (1024)
```text
========================================================
  AWS-LC ML-KEM-1024 Validation (vs NIST)
========================================================

Total Vectors: 50
Valid Vectors: 50
✔ All vectors valid

Accuracy: 100.00%
```


==========================================================
  FINAL SUMMARY (CLEAN VIEW)
==========================================================
```text
  Summary for WolfSSL ML-KEM-512
  KeyGen Passed:         25
  Encapsulation Passed:  25
  Summary for WolfSSL ML-KEM-768
  KeyGen Passed:         25
  Encapsulation Passed:  25
  Summary for WolfSSL ML-KEM-1024
  KeyGen Passed:         25
  Encapsulation Passed:  25
  AWS-LC ML-KEM-512 Validation (vs NIST)
Valid Vectors: 50
Accuracy: 100.00%
  AWS-LC ML-KEM-768 Validation (vs NIST)
Valid Vectors: 50
Accuracy: 100.00%
  AWS-LC ML-KEM-1024 Validation (vs NIST)
Valid Vectors: 50
Accuracy: 100.00%
```
