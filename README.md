# TFHE-go

TFHE-go is a Go implementation of TFHE[[CGGI16](https://eprint.iacr.org/2018/421)] Scheme. The structure of this library is similar to another great Go-based FHE library, [Lattigo](https://github.com/tuneinsight/lattigo).

Some of the implementations are taken from the excellent [TFHE-rs](https://github.com/zama-ai/tfhe-rs), developed by Zama. The goal is to implement most of the functionalities that TFHE-rs provides, with readable code and minimal performance overhead.

This library was not audited or reviewed by security experts, so I do not recommend this library for any real-world production uses.

## Roadmap
- [ ] Binary TFHE (tfheb)
- [ ] Integer TFHE (tfhe)

## Notes
TFHE-go uses [gosl/fun/fftw](https://github.com/cpmech/gosl) as FFT backend, so FFTW has to be installed in your system. You can set the include path using `CGO_` enviornment variables. For example, Homebrew in Apple Silicon installs libraries in `/opt/homebrew` by default, so you need to set
```
export CGO_CFLAGS="-I/opt/homebrew/include"
export CGO_LDFLAGS="-L/opt/homebrew/lib"
```

## References
- TFHE: Fast Fully Homomorphic Encryption over the Torus (https://eprint.iacr.org/2018/421)
- Guide to Fully Homomorphic Encryption over the Discretized Torus (https://eprint.iacr.org/2021/1402)
- Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform (https://eprint.iacr.org/2021/480)
- Parameter Optimization & Larger Precision for (T)FHE (https://eprint.iacr.org/2022/704)
