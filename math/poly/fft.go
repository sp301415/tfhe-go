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
	// fp holds the fourier polynomial.
	fp FourierPoly
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
		fp:    NewFourierPoly(N),
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

// Clear clears all the coefficients to zero.
func (p FourierPoly) Clear() {
	for i := range p.Coeffs {
		p.Coeffs[i] = 0
	}
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
		fp.Coeffs[j] = complex(num.ToWrappingFloat64(p.Coeffs[j]), num.ToWrappingFloat64(p.Coeffs[j+N/2])) * f.wj[j]
	}

	// FFT
	f.fftHalf.Coefficients(fp.Coeffs, fp.Coeffs)
}

// ToScaledFourierPoly transforms Poly to FourierPoly and returns it.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f FourierTransformer[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyInPlace(p, fp)
	return fp
}

// ToScaledFourierPolyInPlace transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f FourierTransformer[T]) ToScaledFourierPolyInPlace(p Poly[T], fp FourierPoly) {
	N := f.degree
	scale := complex(math.Pow(2, -float64(num.SizeT[T]())), 0)

	// Fold and Twist
	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(num.ToWrappingFloat64(p.Coeffs[j]), num.ToWrappingFloat64(p.Coeffs[j+N/2])) * f.wj[j] * scale
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
	NHalf := complex(float64(N/2), 0)

	// InvFFT
	f.fftHalf.Sequence(f.buffer.fpInv.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j] / NHalf
		p.Coeffs[j] = num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] = num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly and returns it.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyInPlace(fp, p)
	return p
}

// ToScaledStandardPolyInPlace transforms FourierPoly to Poly.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolyInPlace(fp FourierPoly, p Poly[T]) {
	N := f.degree
	NHalf := complex(float64(N/2), 0)
	scale := complex(math.Pow(2, float64(num.SizeT[T]())), 0)

	// InvFFT
	f.fftHalf.Sequence(f.buffer.fpInv.Coeffs, fp.Coeffs)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j] * scale / NHalf
		p.Coeffs[j] = num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] = num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// Add adds fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.AddInPlace(fp0, fp1, fp)
	return fp
}

// AddInPlace adds fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) AddInPlace(fp0, fp1, fpOut FourierPoly) {
	vec.AddInPlace(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// AddAssign adds fp0 to ptOut.
func (f FourierTransformer[T]) AddAssign(fp0, fpOut FourierPoly) {
	vec.AddAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Sub subtracts fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.SubInPlace(fp0, fp1, fp)
	return fp
}

// SubInPlace subtracts fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) SubInPlace(fp0, fp1, fpOut FourierPoly) {
	vec.SubInPlace(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// SubAssign subtracts fp0 from fpOut.
func (f FourierTransformer[T]) SubAssign(fp0, fpOut FourierPoly) {
	vec.SubAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Neg negates fp0 and returns the result.
func (f FourierTransformer[T]) Neg(fp0 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.NegInPlace(fp0, fp)
	return fp
}

// NegInPlace negates fp0 and writes it to fpOut.
func (f FourierTransformer[T]) NegInPlace(fp0, fpOut FourierPoly) {
	vec.NegInPlace(fp0.Coeffs, fpOut.Coeffs)
}

// NegAssign negates fp0.
func (f FourierTransformer[T]) NegAssign(fp0 FourierPoly) {
	vec.NegAssign(fp0.Coeffs)
}

// Mul multiplies fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulInPlace(fp0, fp1, fp)
	return fp
}

// MulInPlace multiplies fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) MulInPlace(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulInPlace(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAssign multiplies fp0 to fpOut.
func (f FourierTransformer[T]) MulAssign(fp0, fpOut FourierPoly) {
	vec.ElementWiseMulAssign(fp0.Coeffs, fpOut.Coeffs)
}

// MulAddAssign multiplies fp0, fp1 and adds it to fpOut.
func (f FourierTransformer[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f FourierTransformer[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulSubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulWithStandard multiplies fp0, p1 and returns the result.
func (f FourierTransformer[T]) MulWithStandard(fp0, p1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulInPlace(fp0, p1, fp)
	return fp
}

// MulWithStandardInPlace multiplies fp0, p1 and writes it to fpOut.
func (f FourierTransformer[T]) MulWithStandardInPlace(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p1, f.buffer.fp)

	vec.ElementWiseMulInPlace(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// MulWithStandardAssign multiplies p0 to fpOut.
func (f FourierTransformer[T]) MulWithStandardAssign(p0 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p0, f.buffer.fp)

	vec.ElementWiseMulAssign(f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// MulWithStandardAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f FourierTransformer[T]) MulWithStandardAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p1, f.buffer.fp)

	vec.ElementWiseMulAddAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f FourierTransformer[T]) MulWithStandardSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p1, f.buffer.fp)

	vec.ElementWiseMulSubAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// ScalarMul multplies c to fp0 and returns the result.
func (f FourierTransformer[T]) ScalarMul(fp0 FourierPoly, c float64) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ScalarMulInPlace(fp0, c, fp)
	return fp
}

// ScalarMulInPlace multplies c to fp0 and writes it to fpOut.
func (f FourierTransformer[T]) ScalarMulInPlace(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	vec.ScalarMulInPlace(fp0.Coeffs, complex(c, 0), fpOut.Coeffs)
}

// ScalarMulAssign multplies c to fpOut.
func (f FourierTransformer[T]) ScalarMulAssign(c float64, fpOut FourierPoly) {
	vec.ScalarMulAssign(complex(c, 0), fpOut.Coeffs)
}

// ScalarDiv divides c from fp0 and returns the result.
func (f FourierTransformer[T]) ScalarDiv(fp0 FourierPoly, c complex128) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ScalarDivInPlace(fp0, c, fp)
	return fp
}

// ScalarDivInPlace divides c from fp0 and writes it to fpOut.
func (f FourierTransformer[T]) ScalarDivInPlace(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	for i := 0; i < f.degree; i++ {
		fpOut.Coeffs[i] = fp0.Coeffs[i] / c
	}
}

// ScalarDivAssign divides c from fpOut.
func (f FourierTransformer[T]) ScalarDivAssign(c float64, fpOut FourierPoly) {
	for i := 0; i < f.degree; i++ {
		fpOut.Coeffs[i] /= complex(c, 0)
	}
}
