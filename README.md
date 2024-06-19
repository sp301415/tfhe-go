<h1 align="center">TFHE-go</h1>
<p align="center">Go implementation of (MK)TFHE scheme</p>
<p align="center">
  <a href="https://pkg.go.dev/github.com/sp301415/tfhe-go"><img src="https://pkg.go.dev/badge/github.com/sp301415/tfhe-go.svg"/></a>
  <a href="https://goreportcard.com/report/github.com/sp301415/tfhe-go"><img src="https://goreportcard.com/badge/github.com/sp301415/tfhe-go"/></a>
  <img src="https://github.com/sp301415/tfhe-go/actions/workflows/ci.yml/badge.svg"/></a>
</p>
<p align="center"><img src="LOGO.png" width="300"/></p>

> [!IMPORTANT]
> TFHE-go is still under heavy development. There may be backward-incompatible changes at any time.

**TFHE-go** is a Go implementation of TFHE[[CGGI16](https://eprint.iacr.org/2016/870)] and Multi-Key TFHE[[KMS22](https://eprint.iacr.org/2022/1460)] scheme. It provides:
- Support for binary and integer TFHE and its multi-key variant
- Pure Go implementation, along with SIMD-accelerated Go Assembly on amd64 platforms
- Comparable performance to state-of-the-art C++/Rust libraries
- Readable code and user-friendly API using modern Go features like generics

The goal of this library is to be fast, simple and versatile, offering a robust basis for researchers and developers interested in TFHE. The overall structure and design is heavily influenced by two excellent FHE libraries: [Lattigo](https://github.com/tuneinsight/lattigo) by [Tune Insight](https://tuneinsight.com), and [TFHE-rs](https://github.com/zama-ai/tfhe-rs) by [Zama](https://zama.ai).

## Installation
You can install TFHE-go in your project using `go get`:
```
$ go get -u github.com/sp301415/tfhe-go
```
TFHE-go uses Go Assembly for SIMD operations on amd64 platforms. To disable this, you can pass `purego` [build tag](https://pkg.go.dev/go/build#hdr-Build_Constraints).

## Examples
### Encryption
```go
// Parameters must be compiled before use.
params := tfhe.ParamsUint4.Compile()

// Set up Encryptor.
enc := tfhe.NewEncryptor(params)

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

// Set up Evaluator.
// Note that we don't need evaluation key for CMUX.
eval := tfhe.NewEvaluatorWithoutKey(params)

ctOut := eval.CMux(ctFlag, ct0, ct1)
fmt.Println(enc.DecryptGLWE(ctOut)[0]) // 5
```

### Programmable Bootstrapping
```go
params := tfhe.ParamsUint4.Compile()

enc := tfhe.NewEncryptor(params)

ct := enc.EncryptLWE(3)

// Set up Evaluator with EvaluationKey.
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

### Multi-Key TFHE
```go
// This parameters can take up to two parties.
params := mktfhe.ParamsBinaryParty2.Compile()

// Sample a seed for CRS.
seed := make([]byte, 512)
rand.Read(seed)

// Each Encryptor should be marked with index.
enc0 := mktfhe.NewBinaryEncryptor(params, 0, seed)
enc1 := mktfhe.NewBinaryEncryptor(params, 1, seed)

// Set up Decryptor.
// In practice, one should use a distributed decryption protocol
// to decrypt multi-key ciphertexts.
// However, in multi-key TFHE, this procedure is very difficult and slow.
// Therefore, we use a trusted third party for decryption.
dec := mktfhe.NewBinaryDecryptor(params, map[int]tfhe.SecretKey[uint64]{
  0: enc0.BaseEncryptor.SecretKey,
  1: enc1.BaseEncryptor.SecretKey,
})

ct0 := enc0.EncryptLWEBool(true)
ct1 := enc1.EncryptLWEBool(false)

// Set up Evaluator.
eval := mktfhe.NewBinaryEvaluator(params, map[int]mktfhe.EvaluationKey[uint64]{
  0: enc0.GenEvaluationKeyParallel(),
  1: enc1.GenEvaluationKeyParallel(),
})

// Execute AND operation in parallel.
ctOut := eval.ANDParallel(ct0, ct1)

fmt.Println(dec.DecryptLWEBool(ctOut)) // false
```

## Benchmarks
All benchmarks were measured on a machine equipped with Intel Xeon Platinum 8268 CPU @ 2.90GHz and 384GB of RAM. Roughly equivalent parameters were used.

|Operation|TFHE-go|TFHE-rs (v0.6.1)|
|---------|-------|-------|
|Gate Bootstrapping|10.08ms|10.84ms|
|Programmable Bootstrapping (6 bits)|36.51ms|89.48ms|

You can use the standard go test tool to reproduce benchmarks:
```
$ go test ./tfhe -run=^$ -bench="GateBootstrap|ProgrammableBootstrap"
```


## Security
TFHE-go has not been audited or reviewed by security experts, and may contain critical vulnerabilities. Use at your own risk. See [SECURITY](https://github.com/sp301415/tfhe-go/blob/master/SECURITY.md) for more details.

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

## Acknowledgements
Special thanks to Seonhong Min([@snu-lukemin](https://github.com/snu-lukemin)) for providing many helpful insights.
TFHE-go logo is designed by [@mlgng2010](https://www.instagram.com/mlgng2010/), based on the Go Gopher by [Renee French](https://reneefrench.blogspot.com).

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
- TFHE Public-Key Encryption Revisited (https://eprint.iacr.org/2023/603)
- Towards Practical Multi-key TFHE: Parallelizable, Key-Compatible, Quasi-linear Complexity (https://eprint.iacr.org/2022/1460)
