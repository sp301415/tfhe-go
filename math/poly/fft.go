package poly

import (
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

// FourierPoly is a polynomial with Fourier Transform already applied.
// More precisely, the "FFT" phase of convolve() are precomputed.
type FourierPoly struct {
	// Coeffs has legnth Degree / 2.
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

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (e Evaluater[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(e.degree)
	e.ToFourierPolyInPlace(p, fp)
	return fp
}

// ToFourierPolyInPlace transforms Poly to FourierPoly.
func (e Evaluater[T]) ToFourierPolyInPlace(p Poly[T], fp FourierPoly) {
	N := e.degree

	// Fold and Twist
	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(p.Coeffs[j+N/2])) * e.wj[j]
	}

	// FFT
	e.fftHalf.Coefficients(fp.Coeffs, fp.Coeffs)
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
func (e Evaluater[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](e.degree)
	e.ToStandardPolyInPlace(fp, p)
	return p
}

// ToStandardPolyInPlace transforms FourierPoly to Poly.
func (e Evaluater[T]) ToStandardPolyInPlace(fp FourierPoly, p Poly[T]) {
	N := e.degree

	// InvFFT
	e.fftHalf.Sequence(e.buffInvFP.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		e.buffInvFP.Coeffs[j] *= e.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] = num.FromFloat64[T](real(e.buffInvFP.Coeffs[j]))
		p.Coeffs[j+N/2] = num.FromFloat64[T](imag(e.buffInvFP.Coeffs[j]))
	}
}

// toStandardPolyAddInPlace transforms FourierPoly to Poly, and adds it to p.
func (e Evaluater[T]) toStandardPolyAddInPlace(fp FourierPoly, p Poly[T]) {
	N := e.degree

	// InvFFT
	e.fftHalf.Sequence(e.buffInvFP.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		e.buffInvFP.Coeffs[j] *= e.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] += num.FromFloat64[T](real(e.buffInvFP.Coeffs[j]))
		p.Coeffs[j+N/2] += num.FromFloat64[T](imag(e.buffInvFP.Coeffs[j]))
	}
}

// ToStandardPolyAddInPlace transforms FourierPoly to Poly, and subtracts it from p.
func (e Evaluater[T]) toStandardPolySubInPlace(fp FourierPoly, p Poly[T]) {
	N := e.degree

	// InvFFT
	e.fftHalf.Sequence(e.buffInvFP.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		e.buffInvFP.Coeffs[j] *= e.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] -= num.FromFloat64[T](real(e.buffInvFP.Coeffs[j]))
		p.Coeffs[j+N/2] -= num.FromFloat64[T](imag(e.buffInvFP.Coeffs[j]))
	}
}
