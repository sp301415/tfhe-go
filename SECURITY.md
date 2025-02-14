# Security
Theoretical security of TFHE is based on hardness of [LWE](https://en.wikipedia.org/wiki/Learning_with_errors) and [RLWE](https://en.wikipedia.org/wiki/Ring_learning_with_errors) problem, which are the foundations of lattice-based cryptography.

## Implementation-related Attacks
TFHE-go has not been audited or reviewed by security experts. It is highly likely that it contains critical vulnerabilities to implementation-related attacks, such as side-channel attacks. Use at your own risk.

## Parameter Selection
Single-Key parameters of TFHE-go ensure at least 128 bits of security, with bootstrapping failure rate less than 2<sup>-64</sup>. Multi-Key parameters are based on [[KMS22](https://eprint.iacr.org/2022/1460)], which ensure at least 110 bits of security. They were validated using latest commit([dfbc622](https://github.com/malb/lattice-estimator/commit/dfbc6222eb32db0d595bc45473c22c5d315de4f4)) of [lattice-estimator](https://github.com/malb/lattice-estimator). Attack costs were estimated with two strategies, `primal_usvp` and `dual_hybrid`, with `red_cost_model = RC.BDGL16`.

### Block Binary Keys

TFHE-go implements block binary distribution [[LMSS23](https://eprint.iacr.org/2023/958)] for sampling secret keys, which may lower the security level. Impacted parameters were carefully adjusted following the authors' security estimation to support 128 bit security. To use uniform binary secret keys like the original TFHE scheme, you can set `BlockSize` to 1.

### IND-CPA<sup>D</sup> Security
Recently, [[CCP+24](https://eprint.iacr.org/2024/127)] proposed an attack against TFHE over IND-CPA<sup>D</sup> security model. This attack may be effective, often resulting in full key recovery, if bootstrapping failure proabability is high enough. TFHE-go only considers IND-CPA security, and assumes that decrypted plaintexts are not shared with any third parties. If you need such functionality, you must use parameters with lower bootstrapping failure rate.

## Distributed Decryption
In multi-key FHE schemes, decrypting a ciphertext requires all parties to engage in a distributed decryption protocol, which allows parties to obtain decrypted messages without any information leak. However, in multi-key TFHE, this protocol is typically expensive, requring multy-party garbling [[Ben18](https://eprint.iacr.org/2017/1186)] or modified noise flooding [[DDK+23](https://eprint.iacr.org/2023/815)]. For simplicity, TFHE-go assumes the presence of a trusted third party (known as the *Decryptor*) who possesses the secret keys of all parties to decrypt ciphertexts.
