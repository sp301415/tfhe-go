package poly

import (
	"math"
	"math/cmplx"

	"github.com/cpmech/gosl/fun/fftw"
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

// FourierTransformer calculates algorithms related to FFT,
// most notably the polynomial multiplication.
//
// While FFT is much faster than Evaluater's karatsuba multiplication,
// in TFHE it is used sparsely because of float64 precision.
//
// Evaluater uses fftw as backend, so manually freeing memory is needed.
// Use defer clause after initialization:
//
//	fft := poly.NewFourierTransformer[T](N)
//	defer fft.Free()
type FourierTransformer[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handlf.
	degree int
	// maxT is a float64 value of 2^sizeT.
	maxT float64

	// fft holds fftw plan for FFT.
	fft *fftw.Plan1d
	// fftInv holds fftw plan for inverse FFT.
	fftInv *fftw.Plan1d

	// wj holds the precomputed values of w_2N^j where j = 0 ~ N.
	wj []complex128
	// wjInv holds the precomputed values of w_2N^-j where j = 0 ~ N.
	wjInv []complex128

	buffer fftBuffer[T]
}

// fftBuffer contains buffer values for FourierTransformer.
type fftBuffer[T num.Integer] struct {
	// fp holds the fourier polynomial.
	// The coefficients of fp is referenced by fftw.
	fp FourierPoly
	// fpInv holds the InvFTT & Untwisted & Unfolded value of fp.
	// The coefficients of fpInv is referenced by fftw.
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

	buffer := newfftBuffer[T](N)

	return FourierTransformer[T]{
		degree: N,
		maxT:   math.Exp2(float64(num.SizeT[T]())),

		fft:    fftw.NewPlan1d(buffer.fp.Coeffs, false, true),
		fftInv: fftw.NewPlan1d(buffer.fpInv.Coeffs, true, true),

		wj:    wj,
		wjInv: wjInv,

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
	buffer := newfftBuffer[T](f.degree)

	return FourierTransformer[T]{
		degree: f.degree,
		maxT:   f.maxT,

		fft:    fftw.NewPlan1d(buffer.fp.Coeffs, false, true),
		fftInv: fftw.NewPlan1d(buffer.fpInv.Coeffs, true, true),

		wj:    f.wj,
		wjInv: f.wjInv,

		buffer: buffer,
	}
}

// Free frees internal fftw data.
func (f FourierTransformer[T]) Free() {
	f.fft.Free()
	f.fftInv.Free()
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

// toFloat64 returns x as float64.
func (f FourierTransformer[T]) toFloat64(x T) float64 {
	var z T
	switch any(z).(type) {
	case uint, uintptr:
		return float64(int(x))
	case uint8:
		return float64(int8(x))
	case uint16:
		return float64(int16(x))
	case uint32:
		return float64(int32(x))
	case uint64:
		return float64(int64(x))
	}
	return float64(x)
}

// toScaledFloat64 returns scaled x as float64.
func (f FourierTransformer[T]) toScaledFloat64(x T) float64 {
	return f.toFloat64(x) / f.maxT
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
		f.buffer.fp.Coeffs[j] = complex(f.toFloat64(p.Coeffs[j]), f.toFloat64(p.Coeffs[j+N/2])) * f.wj[j]
	}

	// FFT
	f.fft.Execute()
	fp.CopyFrom(f.buffer.fp)
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

	// Fold and Twist
	for j := 0; j < N/2; j++ {
		f.buffer.fp.Coeffs[j] = complex(f.toScaledFloat64(p.Coeffs[j]), f.toScaledFloat64(p.Coeffs[j+N/2])) * f.wj[j]
	}

	// FFT
	f.fft.Execute()
	fp.CopyFrom(f.buffer.fp)
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
	NHalf := float64(N / 2)

	// InvFFT
	f.buffer.fpInv.CopyFrom(fp)
	f.fftInv.Execute()

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j]
		p.Coeffs[j] = T(math.Round(real(f.buffer.fpInv.Coeffs[j]) / NHalf))
		p.Coeffs[j+N/2] = T(math.Round(imag(f.buffer.fpInv.Coeffs[j]) / NHalf))
	}
}

// fromScaledFloat64 returns T value from scaled float64 value.
func (f FourierTransformer[T]) fromScaledFloat64(x float64) T {
	fr := x - math.Round(x)
	fr *= f.maxT
	fr = math.Round(fr)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		return T(int(fr))
	case uint8:
		return T(int8(fr))
	case uint16:
		return T(int16(fr))
	case uint32:
		return T(int32(fr))
	case uint64:
		return T(int64(fr))
	}
	return T(fr)
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
	NHalf := float64(N / 2)

	// InvFFT
	f.buffer.fpInv.CopyFrom(fp)
	f.fftInv.Execute()

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j]
		p.Coeffs[j] = f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]) / NHalf)
		p.Coeffs[j+N/2] = f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]) / NHalf)
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree
	NHalf := float64(N / 2)

	// InvFFT
	f.buffer.fpInv.CopyFrom(fp)
	f.fftInv.Execute()

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j]
		p.Coeffs[j] += f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]) / NHalf)
		p.Coeffs[j+N/2] += f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]) / NHalf)
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
// Each coefficients are scaled by 2^sizeT.
func (f FourierTransformer[T]) ToScaledStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree
	NHalf := float64(N / 2)

	// InvFFT
	f.buffer.fpInv.CopyFrom(fp)
	f.fftInv.Execute()

	// Untwist and Unfold
	for j := 0; j < N/2; j++ {
		f.buffer.fpInv.Coeffs[j] *= f.wjInv[j]
		p.Coeffs[j] -= f.fromScaledFloat64(real(f.buffer.fpInv.Coeffs[j]) / NHalf)
		p.Coeffs[j+N/2] -= f.fromScaledFloat64(imag(f.buffer.fpInv.Coeffs[j]) / NHalf)
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

// PolyMul multiplies fp0, p1 and returns the result.
func (f FourierTransformer[T]) PolyMul(fp0, p1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulInPlace(fp0, p1, fp)
	return fp
}

// PolyMulInPlace multiplies fp0, p1 and writes it to fpOut.
func (f FourierTransformer[T]) PolyMulInPlace(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p1, f.buffer.fp)

	vec.ElementWiseMulInPlace(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAssign multiplies p0 to fpOut.
func (f FourierTransformer[T]) PolyMulAssign(p0 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p0, f.buffer.fp)

	vec.ElementWiseMulAssign(f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f FourierTransformer[T]) PolyMulAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyInPlace(p1, f.buffer.fp)

	vec.ElementWiseMulAddAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign multiplies fp0, p1 and subtracts it from fpOut.
func (f FourierTransformer[T]) PolyMulSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
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
