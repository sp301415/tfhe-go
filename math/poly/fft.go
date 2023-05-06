package poly

import (
	"math"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/slices"
)

// FFT calculates the Fourier Transform of src, and stores it to dst.
func (e Evaluater[T]) FFT(src []float64, dst []complex128) {
	e.fft.Coefficients(dst, src)
}

// InvFFT calculates the Inverse Fourier Transform of src, and stores it to dst.
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

// FourierPoly is a polynomial with Fourier Transform already applied.
// More precisely, the "FFT" phase of convolve() are precomputed.
type FourierPoly struct {
	Coeffs []complex128
}

// NewFourierPoly creates a fourier polynomial with degree N with empty coefficients.
// N should be power of two. Otherwise, it panics.
func NewFourierPoly(N int) FourierPoly {
	if !num.IsPowerOfTwo(N) {
		panic("degree not power of two")
	}
	return FourierPoly{Coeffs: make([]complex128, N/2)}
}

// Degree returns the degree of the polynomial.
func (p FourierPoly) Degree() int {
	return len(p.Coeffs) * 2
}

// Copy returns a copy of the polynomial.
func (p FourierPoly) Copy() FourierPoly {
	return FourierPoly{Coeffs: slices.Clone(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p FourierPoly) CopyFrom(p0 FourierPoly) {
	copy(p.Coeffs, p0.Coeffs)
}

// ToFourierPoly transforms Poly to FourierPoly, optimized for multiplication later.
func (e Evaluater[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	N := e.degree
	fp := FourierPoly{Coeffs: make([]complex128, N/2)}

	// Fold
	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(p.Coeffs[j+N/2]))
	}

	// Twist
	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] *= e.wj[j]
	}

	// FFT
	e.fftHalf.Coefficients(fp.Coeffs, fp.Coeffs)

	return fp
}

// MulWithFourier multiplies p0, fp and returns the result.
func (e Evaluater[T]) MulWithFourier(p0 Poly[T], fp FourierPoly) Poly[T] {
	p := New[T](e.degree)
	e.MulWithFourierInPlace(p0, fp, p)
	return p
}

// MulWithFourierInPlace multiplies p0, fp and writes it to pOut.
func (e Evaluater[T]) MulWithFourierInPlace(p0 Poly[T], fp FourierPoly, pOut Poly[T]) {
	N := e.degree / 2

	// Fold
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] = complex(float64(p0.Coeffs[j]), float64(p0.Coeffs[j+N/2]))
	}

	// Twist
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] *= e.wj[j]
	}

	// FFT
	e.fftHalf.Coefficients(e.buffp0c, e.buffp0c)

	// Pointwise Multiplication
	for j := 0; j < N/2; j++ {
		e.buffp0c[j] *= fp.Coeffs[j]
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
		pOut.Coeffs[j] = T(math.Round(real(e.buffp0c[j])))
		pOut.Coeffs[j+N/2] = T(math.Round(imag(e.buffp0c[j])))
	}

}

// MulWithFourierAssign multiplies p0 to pOut.
func (e Evaluater[T]) MulWithFourierAssign(fp FourierPoly, pOut Poly[T]) {
	e.MulWithFourierInPlace(pOut, fp, pOut)
}
