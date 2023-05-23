# TFHE-go

TFHE-go is a Go implementation of TFHE[[CGGI16](https://eprint.iacr.org/2018/421)] Scheme. The structure of this library is similar to another great Go-based FHE library, [Lattigo](https://github.com/tuneinsight/lattigo).

Some of the implementations are taken from the excellent [TFHE-rs](https://github.com/zama-ai/tfhe-rs), developed by Zama. The goal is to implement most of the functionalities that TFHE-rs provides, with readable code and minimal performance overhead.

This library was not audited or reviewed by security experts, so I do not recommend this library for any real-world production uses.


## Notes
TFHE-go uses [gosl/fun/fftw](https://github.com/cpmech/gosl) as FFT backend, so FFTW has to be installed in your system. You can set the include path using `CGO_` enviornment variables. For example, Homebrew in Apple Silicon installs libraries in `/opt/homebrew` by default, so you need to set
```bash
export CGO_CFLAGS="-I/opt/homebrew/include"
export CGO_LDFLAGS="-L/opt/homebrew/lib"
```

## Examples
### Encryption
```go
params := tfhe.ParamsUint4.Compile()   // Parameters should be compiled before use.

enc := tfhe.NewEncrypter(params) // Set up Encrypter.
defer enc.Free()                 // Cleanup internal FFTW values.

ctLWE := enc.EncryptLWE(4)
ctGLWE := enc.EncryptGLWE([]int{1, 2, 3, 4})

// Decrypt Everything!
fmt.Println(enc.DecryptLWE(ctLWE))       // 4
fmt.Println(enc.DecryptGLWE(ctGLWE)[:4]) // [1, 2, 3, 4]
```

### CMUX
```go
params := tfhe.ParamsUint4.Compile()
decompParams := params.KeySwitchParameters()

enc := tfhe.NewEncrypter(params)
defer enc.Free()

ct0 := enc.EncryptGLWE([]int{2})
ct1 := enc.EncryptGLWE([]int{5})
ctFlag := enc.EncryptFourierGGSW([]int{1}, decompParams)

eval := tfhe.NewEvaluaterWithoutKey(params)
defer eval.Free()

ctOut := eval.CMuxFourier(ctFlag, ct0, ct1)
fmt.Println(enc.DecryptPacked(ctOut)[0]) // 5
```

### Programmable Bootstrapping
```go
params := tfhe.ParamsUint4.Compile()

enc := tfhe.NewEncrypter(params)
defer enc.Free()

ct := enc.Encrypt(3)
evalKey := enc.GenEvaluationKeyParallel()

eval := tfhe.NewEvaluater(params, evalKey)
defer eval.Free()

ctOut := eval.BootstrapFunc(ct, func(x int) int { return 2*x + 1 })
fmt.Println(enc.Decrypt(ctOut)) // 7 = 2*3+1
```

## Benchmarks
All results were measured from Apple M1. `ParamsBoolean` and `ParamsUint6` are used.
|Operations|Time|
|----------|----|
|Bootstrapping Key Generation (Parallel)|2.804s ± 1%|
|Programmable Bootstrapping|273.0m ± 0%|
|Gate Bootstrapping|37.93m ± 0%|

## References
- TFHE: Fast Fully Homomorphic Encryption over the Torus (https://eprint.iacr.org/2018/421)
- Guide to Fully Homomorphic Encryption over the Discretized Torus (https://eprint.iacr.org/2021/1402)
- Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform (https://eprint.iacr.org/2021/480)
- Parameter Optimization & Larger Precision for (T)FHE (https://eprint.iacr.org/2022/704)
