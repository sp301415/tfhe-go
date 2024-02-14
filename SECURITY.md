# Security
Theoretical security of TFHE is based on hardness of [LWE](https://en.wikipedia.org/wiki/Learning_with_errors) and [RLWE](https://en.wikipedia.org/wiki/Ring_learning_with_errors) problem, which are the foundations of Lattice-based cryptography.

## Implementation-related Attacks
TFHE-go has not been audited or reviewed by security experts. It is highly likely that it contains critical vulnerabilities to implementation-related attacks, such as side-channel attacks. Using it for any real-world production purposes is not recommended.

## Parameter Selection
All parameters of TFHE-go is based on [TFHE-rs](https://github.com/zama-ai/tfhe-rs), and ensures at least 128 bits of security. They were validated using latest commit([5350825](https://github.com/malb/lattice-estimator/commit/53508253629d3b5d31a2ad110e85dc69391ccb95)) of [lattice-estimator](https://github.com/malb/lattice-estimator). Attack costs were estimated with two strategies, `primal_usvp` and `dual_hybrid`, with `red_cost_model = RC.BDGL16`.

TFHE-go implements Block Binary Distribution[[LMSS23](https://eprint.iacr.org/2023/958)] for sampling secret key, which may lower the security level. Impacted parameters were carefully adjusted following the authors' security estimation to support 128 bit security. To use uniform binary secret keys like the original TFHE scheme, you can set `BlockSize` to 1.

## IND-CPA<sup>D</sup> Security
In [[CCP+24](https://eprint.iacr.org/2024/127)], the authors propose KR<sup>D</sup> attack on TFHE scheme, which exploits bootstrapping failure caused by rounding noise exceeding the noise budget. This may be effective, often resulting in full key recovery, if bootstrapping failure proabability is high enough. To accomodate this, all parameters in TFHE-go is set to have failure probability lower than 2^-100, which can be considered negligible.
