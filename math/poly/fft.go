package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
	"gonum.org/v1/gonum/dsp/fourier"
)

// FourierTransformer calculates algorithms related to FFT,
// most notably the polynomial multiplication.
//
// While FFT is much faster than Evaluater's karatsuba multiplication,
// in TFHE it is used sparsely because of float64 precision.
type FourierTransformer[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handlf.
	degree int

	// fft holds gonum's fourier.FFT.
	fft *fourier.FFT
	// fftHalf holds gonum's fourier.CmplxFFT for N/2. Used for negacyclic convolution.
	fftHalf *fourier.CmplxFFT

	// wj holds the precomputed values of w_2N^j where j = 0 ~ N.
	wj []complex128
	// wjInv holds the precomputed values of w_2N^-j where j = 0 ~ N.
	wjInv []complex128

	buffer fftBuffer[T]
}

// fftBuffer contains buffer values for FourierTransformer.
type fftBuffer[T num.Integer] struct {
	// p0 holds the standard polynomial p0.
	p0 Poly[T]
	// p1 holds the standard polynomial p1.
	p1 Poly[T]
	// pOut holds the standard polynomial pOut.
	pOut Poly[T]
	// fpInv holds the InvFTT & Untwisted & Unfolded value of fp.
	fpInv FourierPoly
}

// NewFourierTransformer creates a new FourierTransformer with degree N.
// N should be power of two.
func NewFourierTransformer[T num.Integer](N int) FourierTransformer[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	wj := make([]complex128, N)
	wjInv := make([]complex128, N)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		wj[j] = cmplx.Exp(complex(0, e))
		wjInv[j] = cmplx.Exp(-complex(0, e))
	}

	return FourierTransformer[T]{
		degree: N,

		fft:     fourier.NewFFT(N),
		fftHalf: fourier.NewCmplxFFT(N / 2),

		wj:    wj,
		wjInv: wjInv,

		buffer: newfftBuffer[T](N),
	}
}

// newFFTBuffer allocates an empty fft buffer.
func newfftBuffer[T num.Integer](N int) fftBuffer[T] {
	return fftBuffer[T]{
		p0:    New[T](N),
		p1:    New[T](N),
		pOut:  New[T](N),
		fpInv: NewFourierPoly(N),
	}
}

// ShallowCopy returns a shallow copy of this FourierTransformer.
// Returned FourierTransformer is safe for concurrent usf.
func (f FourierTransformer[T]) ShallowCopy() FourierTransformer[T] {
	return FourierTransformer[T]{
		degree: f.degree,

		fft:     fourier.NewFFT(f.degree),
		fftHalf: fourier.NewCmplxFFT(f.degree / 2),

		wj:    f.wj,
		wjInv: f.wjInv,

		buffer: newfftBuffer[T](f.degree),
	}
}

// FFT calculates the Fourier Transform of src, and stores it to dst.
func (f FourierTransformer[T]) FFT(src []float64, dst []complex128) {
	f.fft.Coefficients(dst, src)
}

// InvFFT calculates the Inverse Fourier Transform of src, and stores it to dst.
func (f FourierTransformer[T]) InvFFT(src []complex128, dst []float64) {
	f.fft.Sequence(dst, src)
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
	return FourierPoly{Coeffs: vec.Copy(p.Coeffs)}
}

// CopyFrom copies p0 to p.
func (p FourierPoly) CopyFrom(p0 FourierPoly) {
	vec.CopyAssign(p0.Coeffs, p.Coeffs)
}

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (f FourierTransformer[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyInPlace(p, fp)
	return fp
}

// ToFourierPolyInPlace transforms Poly to FourierPoly.
func (f FourierTransformer[T]) ToFourierPolyInPlace(p Poly[T], fp FourierPoly) {
	N := f.degree

	// Fold and Twist
	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(p.Coeffs[j+N/2])) * f.wj[j]
	}

	// FFT
	f.fftHalf.Coefficients(fp.Coeffs, fp.Coeffs)
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
func (f FourierTransformer[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToStandardPolyInPlace(fp, p)
	return p
}

// ToStandardPolyInPlace transforms FourierPoly to Poly.
func (f FourierTransformer[T]) ToStandardPolyInPlace(fp FourierPoly, p Poly[T]) {
	N := f.degree

	// InvFFT
	f.fftHalf.Sequence(f.buffer.fpInv.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] = num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] = num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// toStandardPolyAddInPlace transforms FourierPoly to Poly, and adds it to p.
func (f FourierTransformer[T]) toStandardPolyAddInPlace(fp FourierPoly, p Poly[T]) {
	N := f.degree

	// InvFFT
	f.fftHalf.Sequence(f.buffer.fpInv.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] += num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] += num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// ToStandardPolyAddInPlace transforms FourierPoly to Poly, and subtracts it from p.
func (f FourierTransformer[T]) toStandardPolySubInPlace(fp FourierPoly, p Poly[T]) {
	N := f.degree

	// InvFFT
	f.fftHalf.Sequence(f.buffer.fpInv.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j] / complex(float64(N/2), 0)
		p.Coeffs[j] -= num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] -= num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}
