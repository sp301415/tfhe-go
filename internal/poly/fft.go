package poly

import (
	"math"
)

// FFT calculates the Fourier Transform of src, and stores it in dst & returns it.
// If dst == nil, it allocates a new complex128 slice and returns it.
func (e Evaluater[T]) FFT(src []float64, dst []complex128) {
	e.fft.Coefficients(dst, src)
}

// InvFFT calculates the Inverse Fourier Transform of src, and stores it in dst & returns it.
// If dst == nil, it allocates a new complex128 slice and returns it.
func (e Evaluater[T]) InvFFT(src []complex128, dst []float64) {
	e.fft.Sequence(dst, src)

	for i := range dst {
		dst[i] /= float64(len(dst))
	}
}

// convolve calculates the negacyclic convolution of p0 and p1, and stores it in pOut.
// For detailed algorithm, see https://eprint.iacr.org/2021/480.pdf.
func (e Evaluater[T]) convolve(p0, p1, pOut []float64) {
	N := e.degree

	// Fold
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] = complex(p0[j], p0[j+N/2])
		e.buffp1c[j] = complex(p1[j], p1[j+N/2])
	}

	// Twist
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] *= e.wj[j]
		e.buffp1c[j] *= e.wj[j]
	}

	// FFT
	e.fftHalf.Coefficients(e.buffp0c, e.buffp0c)
	e.fftHalf.Coefficients(e.buffp1c, e.buffp1c)

	// Pointwise Multiplication
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] *= e.buffp1c[j]
	}

	// InvFFT
	e.fftHalf.Sequence(e.buffp0c, e.buffp0c)
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] /= complex(float64(N/2), 0)
	}

	// Untwist
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] *= e.wjInv[j]
	}

	// Unfold
	for j := 0; j < N/2; j++ {
		pOut[j] = math.Round(real(e.buffp0c[j]))
		pOut[j+N/2] = math.Round(imag(e.buffp0c[j]))
	}
}
