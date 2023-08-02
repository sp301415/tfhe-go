package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

// FourierTransformer calculates algorithms related to FFT,
// most notably the polynomial multiplication.
//
// While FFT is much faster than Evaluator's karatsuba multiplication,
// in TFHE it is used sparsely because of float64 precision.
type FourierTransformer[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// maxT is a float64 value of 2^sizeT.
	maxT float64

	// wNj holds the precomputed values of w_N^j where j = 0 ~ N/2.
	wNj []complex128
	// wNjInv holds the precomputed values of w_N^-j where j = 0 ~ N/2.
	wNjInv []complex128
	// w2Nj holds the precomputed values of w_2N^j where j = 0 ~ N/2.
	w2Nj []complex128
	// w2NjInv holds the precomputed values of scaled w_2N^-j / (N / 2) where j = 0 ~ N/2.
	w2NjInv []complex128

	buffer fftBuffer[T]
}

// fftBuffer contains buffer values for FourierTransformer.
type fftBuffer[T num.Integer] struct {
	// fp holds the FFT value of p.
	fp FourierPoly
	// fpInv holds the InvFFT value of fp.
	fpInv FourierPoly
}

// NewFourierTransformer creates a new FourierTransformer with degree N.
// N should be power of two.
func NewFourierTransformer[T num.Integer](N int) FourierTransformer[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	wNj := make([]complex128, N/2)
	wNjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := 2 * math.Pi * float64(j) / float64(N)
		wNj[j] = cmplx.Exp(complex(0, e))
		wNjInv[j] = cmplx.Exp(-complex(0, e))
	}
	vec.BitReverseInPlace(wNj)
	vec.BitReverseInPlace(wNjInv)

	w2Nj := make([]complex128, N/2)
	w2NjInv := make([]complex128, N/2)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		w2Nj[j] = cmplx.Exp(complex(0, e))
		w2NjInv[j] = cmplx.Exp(-complex(0, e)) / complex(float64(N/2), 0)
	}

	buffer := newfftBuffer[T](N)

	return FourierTransformer[T]{
		degree: N,
		maxT:   math.Exp2(float64(num.SizeT[T]())),

		wNj:     wNj,
		wNjInv:  wNjInv,
		w2Nj:    w2Nj,
		w2NjInv: w2NjInv,

		buffer: buffer,
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
		maxT:   f.maxT,

		wNj:     f.wNj,
		wNjInv:  f.wNjInv,
		w2Nj:    f.w2Nj,
		w2NjInv: f.w2NjInv,

		buffer: newfftBuffer[T](f.degree),
	}
}

// FourierPoly is a polynomial with Fourier Transform applied.
type FourierPoly struct {
	// Coeffs has length Degree / 2.
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
func (p *FourierPoly) CopyFrom(p0 FourierPoly) {
	vec.CopyAssign(p0.Coeffs, p.Coeffs)
}

// Clear clears all the coefficients to zero.
func (p FourierPoly) Clear() {
	for i := range p.Coeffs {
		p.Coeffs[i] = 0
	}
}

// FFTInPlace applies FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f FourierTransformer[T]) FFTInPlace(fp FourierPoly) {
	// Implementation of Algorithm 1 from https://eprint.iacr.org/2016/504.pdf
	t := f.degree / 2
	for m := 1; m < f.degree/2; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := fp.Coeffs[j], fp.Coeffs[j+t]*f.wNj[m+i]
				fp.Coeffs[j], fp.Coeffs[j+t] = U+V, U-V
			}
		}
	}
}

// InvFFTInPlace applies Inverse FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f FourierTransformer[T]) InvFFTInPlace(fp FourierPoly) {
	// Implementation of Algorithm 2 from https://eprint.iacr.org/2016/504.pdf
	t := 1
	for m := f.degree / 2; m > 1; m >>= 1 {
		j1 := 0
		h := m / 2
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := fp.Coeffs[j], fp.Coeffs[j+t]
				fp.Coeffs[j], fp.Coeffs[j+t] = U+V, (U-V)*f.wNjInv[h+i]
			}
			j1 += 2 * t
		}
		t <<= 1
	}
}

// toScaledFloat64 returns scaled x as float64.
func (f FourierTransformer[T]) toScaledFloat64(x T) float64 {
	return num.ToFloat64(x) / f.maxT
}

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (f FourierTransformer[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fp)
	return fp
}

// ToFourierPolyAssign transforms Poly to FourierPoly.
func (f FourierTransformer[T]) ToFourierPolyAssign(p Poly[T], fp FourierPoly) {
	N := f.degree

	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(num.ToFloat64(p.Coeffs[j]), -num.ToFloat64(p.Coeffs[j+N/2])) * f.w2Nj[j]
	}

	f.FFTInPlace(fp)
}

// ToScaledFourierPoly transforms Poly to FourierPoly and returns it.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f FourierTransformer[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyAssign(p, fp)
	return fp
}

// ToScaledFourierPolyAssign transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f FourierTransformer[T]) ToScaledFourierPolyAssign(p Poly[T], fp FourierPoly) {
	N := f.degree

	for j := 0; j < N/2; j++ {
		fp.Coeffs[j] = complex(f.toScaledFloat64(p.Coeffs[j]), -f.toScaledFloat64(p.Coeffs[j+N/2])) * f.w2Nj[j]
	}

	f.FFTInPlace(fp)
}

// fromScaledFloat64 returns T value from scaled float64 value.
func (f FourierTransformer[T]) fromScaledFloat64(x float64) T {
	fr := x - math.Round(x)
	fr *= f.maxT
	return num.FromFloat64[T](fr)
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
func (f FourierTransformer[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToStandardPolyAssign(fp, p)
	return p
}

// ToStandardPolyAssign transforms FourierPoly to Poly.
func (f FourierTransformer[T]) ToStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	f.InvFFTInPlace(f.buffer.fpInv)

	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.w2NjInv[j]
		p.Coeffs[j] = num.FromFloat64[T](real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] = -num.FromFloat64[T](imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly and returns it.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, p)
	return p
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	f.InvFFTInPlace(f.buffer.fpInv)

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.w2NjInv[j]
		p.Coeffs[j] = f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] = -f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	f.InvFFTInPlace(f.buffer.fpInv)

	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.w2NjInv[j]
		p.Coeffs[j] += f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] += -f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	f.InvFFTInPlace(f.buffer.fpInv)

	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.w2NjInv[j]
		p.Coeffs[j] -= f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]))
		p.Coeffs[j+N/2] -= -f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]))
	}
}

// Add adds fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.AddAssign(fp0, fp1, fp)
	return fp
}

// AddAssign adds fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) AddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.AddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Sub subtracts fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.SubAssign(fp0, fp1, fp)
	return fp
}

// SubAssign subtracts fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) SubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.SubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Neg negates fp0 and returns the result.
func (f FourierTransformer[T]) Neg(fp0 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.NegAssign(fp0, fp)
	return fp
}

// NegAssign negates fp0 and writes it to fpOut.
func (f FourierTransformer[T]) NegAssign(fp0, fpOut FourierPoly) {
	vec.NegAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Mul multiplies fp0, fp1 and returns the result.
func (f FourierTransformer[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulAssign(fp0, fp1, fp)
	return fp
}

// MulAssign multiplies fp0, fp1 and writes it to fpOut.
func (f FourierTransformer[T]) MulAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddAssign multiplies fp0, fp1 and adds it to fpOut.
func (f FourierTransformer[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f FourierTransformer[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulSubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMul multiplies fp0, p1 and returns the result.
func (f FourierTransformer[T]) PolyMul(fp0 FourierPoly, p1 Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.PolyMulAssign(fp0, p1, fp)
	return fp
}

// PolyMulAssign multiplies fp0, p1 and writes it to fpOut.
func (f FourierTransformer[T]) PolyMulAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f FourierTransformer[T]) PolyMulAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAddAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign multiplies fp0, p1 and subtracts it from fpOut.
func (f FourierTransformer[T]) PolyMulSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulSubAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// ScalarMul multplies c to fp0 and returns the result.
func (f FourierTransformer[T]) ScalarMul(fp0 FourierPoly, c float64) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ScalarMulAssign(fp0, c, fp)
	return fp
}

// ScalarMulAssign multplies c to fp0 and writes it to fpOut.
func (f FourierTransformer[T]) ScalarMulAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	vec.ScalarMulAssign(fp0.Coeffs, complex(c, 0), fpOut.Coeffs)
}
