# TFHE-go

[![Go Reference](https://pkg.go.dev/badge/github.com/sp301415/tfhe-go.svg)](https://pkg.go.dev/github.com/sp301415/tfhe-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sp301415/tfhe-go)](https://goreportcard.com/report/github.com/sp301415/tfhe-go)
![CI Test Status](https://github.com/sp301415/tfhe-go/actions/workflows/ci.yml/badge.svg)

⚠️ TFHE-go is still under heavy devlopment. There may be backward-incompatible changes anytime.

TFHE-go is a pure Go implementation of TFHE[[CGGI16](https://eprint.iacr.org/2016/870)] Scheme. The structure of this library is similar to another great Go-based FHE library, [Lattigo](https://github.com/tuneinsight/lattigo).

This library is heavily influenced by excellent [TFHE-rs](https://github.com/zama-ai/tfhe-rs), developed by [Zama](https://www.zama.ai). The goal is to implement most of the functionalities that TFHE-rs provides, with readable code and minimal performance overhead.

This library was not audited or reviewed by security experts, so I do not recommend this library for any real-world production uses.

## Examples
### Encryption
```go
params := tfhe.ParamsUint4.Compile() // Parameters must be compiled before use.

enc := tfhe.NewEncryptor(params) // Set up Encryptor.

ctLWE := enc.EncryptLWE(4)
ctGLWE := enc.EncryptGLWE([]int{1, 2, 3, 4})

// Decrypt Everything!
fmt.Println(enc.DecryptLWE(ctLWE))       // 4
fmt.Println(enc.DecryptGLWE(ctGLWE)[:4]) // [1, 2, 3, 4]
```

### CMUX
```go
params := tfhe.ParamsUint4.Compile()
decompParams := tfhe.DecompositionParametersLiteral[uint64]{
	Base:  1 << 3,
	Level: 6,
}.Compile()

enc := tfhe.NewEncryptor(params)

ct0 := enc.EncryptGLWE([]int{2})
ct1 := enc.EncryptGLWE([]int{5})
ctFlag := enc.EncryptFourierGGSW([]int{1}, decompParams)

// We don't need evaluation key for CMUX,
// so we can just supply empty key.
eval := tfhe.NewEvaluator(params, tfhe.EvaluationKey[uint64]{})

ctOut := eval.CMux(ctFlag, ct0, ct1)
fmt.Println(enc.DecryptGLWE(ctOut)[0]) // 5
```

### Programmable Bootstrapping
```go
params := tfhe.ParamsUint4.Compile()

enc := tfhe.NewEncryptor(params)

ct := enc.EncryptLWE(3)

eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

ctOut := eval.BootstrapFunc(ct, func(x int) int { return 2*x + 1 })
fmt.Println(enc.DecryptLWE(ctOut)) // 7 = 2*3+1
```

### Comparison using Gate Bootstrapping
```go
params := tfheb.ParamsBoolean.Compile()

enc := tfheb.NewEncryptor(params)
eval := tfheb.NewEvaluator(params, enc.GenEvaluationKeyParallel())

// Change these values yourself!
ct0 := enc.EncryptLWEBits(3)
ct1 := enc.EncryptLWEBits(3)

ctXNOR := tfhe.NewLWECiphertext(params)
ctOut := eval.XNOR(ct0[0], ct1[0])
for i := 1; i < 64; i++ {
	eval.XNORAssign(ct0[i], ct1[i], ctXNOR)
	eval.ANDAssign(ctXNOR, ctOut, ctOut)
}

fmt.Println(enc.DecryptLWEBool(ctOut))
```

## Benchmarks
All results were measured from Intel i5-13400F. `ParamsBoolean` and `ParamsUint6` are used.
|Operation|Timing|
|---------|-------|
|Programmable Bootstrapping|91.82ms ± 0%|
|Gate Bootstrapping|14.02ms ± 1%|

## Roadmap
- [x] Optimze FFT using AVX2 instructions
- [ ] Implement NTT instead of Karatsuba
- [ ] Implement Multi-Key TFHE: [[CCS19](https://eprint.iacr.org/2019/116)], [[KMS23](https://eprint.iacr.org/2022/1460)]

## References
- TFHE: Fast Fully Homomorphic Encryption over the Torus (https://eprint.iacr.org/2018/421)
- Guide to Fully Homomorphic Encryption over the Discretized Torus (https://eprint.iacr.org/2021/1402)
- Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography (https://eprint.iacr.org/2016/504)
- Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform (https://eprint.iacr.org/2021/480)
- Parameter Optimization & Larger Precision for (T)FHE (https://eprint.iacr.org/2022/704)
- Improving TFHE: faster packed homomorphic operations and efficient circuit bootstrapping (https://eprint.iacr.org/2017/430)
- MOSFHET: Optimized Software for FHE over the Torus (https://eprint.iacr.org/2022/515)
- Faster TFHE Bootstrapping with Block Binary Keys (https://eprint.iacr.org/2023/958)
