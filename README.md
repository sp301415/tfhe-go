# TFHE-go

[![Go Reference](https://pkg.go.dev/badge/github.com/sp301415/tfhe-go.svg)](https://pkg.go.dev/github.com/sp301415/tfhe-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sp301415/tfhe-go)](https://goreportcard.com/report/github.com/sp301415/tfhe-go)
![CI Test Status](https://github.com/sp301415/tfhe-go/actions/workflows/ci.yml/badge.svg)

⚠️ TFHE-go is still under heavy development. There may be backward-incompatible changes at any time.

**TFHE-go** is a Go implementation of the TFHE[[CGGI16](https://eprint.iacr.org/2016/870)] scheme. It provides:
- Support for binary and integer TFHE
- Pure Go implementation, along with SIMD-accelerated Go Assembly on amd64 platforms
- Comparable performance to state-of-the-art C++/Rust libraries
- Readable code and user-friendly API using modern Go features like generics

The goal of this library is to be fast, simple and versatile, offering a robust basis for researchers and developers interested in TFHE. The overall structure and design is heavily influenced by two excellent FHE libraries: [Lattigo](https://github.com/tuneinsight/lattigo) by [Tune Insight](https://tuneinsight.com), and [TFHE-rs](https://github.com/zama-ai/tfhe-rs) by [Zama](https://zama.ai).

Please note that this library has not been audited or reviewed by security experts, so using it for any real-world production purposes is not recommended.

## Installation
You can install TFHE-go in your project using `go get`:
```
$ go get -u github.com/sp301415/tfhe-go
```
TFHE-go uses Go Assembly for SIMD operations on amd64 platforms. To disable this, you can pass `purego` [build tag](https://pkg.go.dev/go/build#hdr-Build_Constraints).

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
gadgetParams := tfhe.GadgetParametersLiteral[uint64]{
	Base:  1 << 3,
	Level: 6,
}.Compile()

enc := tfhe.NewEncryptor(params)

ct0 := enc.EncryptGLWE([]int{2})
ct1 := enc.EncryptGLWE([]int{5})
ctFlag := enc.EncryptFourierGGSW([]int{1}, gadgetParams)

// We don't need evaluation key for CMUX.
eval := tfhe.NewEvaluatorWithoutKey(params)

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

### Comparison using Binary TFHE
```go
params := tfhe.ParamsBinary.Compile()

enc := tfhe.NewBinaryEncryptor(params)

// Change these values yourself!
bits := 16
ct0 := enc.EncryptLWEBits(3, bits)
ct1 := enc.EncryptLWEBits(3, bits)

eval := tfhe.NewBinaryEvaluator(params, enc.GenEvaluationKeyParallel())

ctXNOR := tfhe.NewLWECiphertext(params)
ctOut := eval.XNOR(ct0[0], ct1[0])
for i := 1; i < bits; i++ {
	eval.XNORAssign(ct0[i], ct1[i], ctXNOR)
	eval.ANDAssign(ctXNOR, ctOut, ctOut)
}

fmt.Println(enc.DecryptLWEBool(ctOut)) // true
```

## Benchmarks
All results were measured from Intel i5-13400F, with roughly equivalent parameters.
|Operation|TFHE-go|TFHE-rs (v0.4.1)|
|---------|-------|-------|
|Gate Bootstrapping|10.87ms|9.84ms|
|Programmable Bootstrapping (6 bits)|51.06ms|85.26ms|

## License
TFHE-go is licensed under the Apache 2.0 License.

## Citing
To cite TFHE-go, please use the following BibTeX entry:
```tex
@misc{TFHE-go,
  title={{TFHE-go}},
  author={Intak Hwang},
  year={2023},
  howpublished = {Online: \url{https://github.com/sp301415/tfhe-go}},
}
```

## References
- TFHE: Fast Fully Homomorphic Encryption over the Torus (https://eprint.iacr.org/2018/421)
- Guide to Fully Homomorphic Encryption over the Discretized Torus (https://eprint.iacr.org/2021/1402)
- Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography (https://eprint.iacr.org/2016/504)
- Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform (https://eprint.iacr.org/2021/480)
- Parameter Optimization & Larger Precision for (T)FHE (https://eprint.iacr.org/2022/704)
- Improving TFHE: faster packed homomorphic operations and efficient circuit bootstrapping (https://eprint.iacr.org/2017/430)
- MOSFHET: Optimized Software for FHE over the Torus (https://eprint.iacr.org/2022/515)
- Faster TFHE Bootstrapping with Block Binary Keys (https://eprint.iacr.org/2023/958)
- Discretization Error Reduction for Torus Fully Homomorphic Encryption (https://eprint.iacr.org/2023/402)
