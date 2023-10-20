package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// FourierTransformer calculates algorithms related to FFT,
// most notably the polynomial multiplication.
//
// While FFT is much faster than Evaluator's karatsuba multiplication,
// in TFHE it is used sparsely because of float64 precision.
//
// Operations usually take two forms: for example,
//   - Add(p0, p1) is equivalent to var p = p0 + p1.
//   - AddAssign(p0, p1, pOut) is equivalent to pOut = p0 + p1.
//
// Note that usually calling Assign(p0, pOut, pOut) is valid.
// However, for some operations, InPlace methods are implemented separately.
//
// # Warning
//
// For performance reasons, functions in this package usually don't implement bound checks.
// If length mismatch happens, usually the result is wrong.
type FourierTransformer[T num.Integer] struct {
	// degree is the degree of polynomial that this transformer can handle.
	degree int
	// maxT is a float64 value of 2^sizeT.
	maxT float64

	// wNj holds the precomputed values of w_N^j where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNj []complex128
	// wNjInv holds the precomputed values of w_N^-j where j = 0 ~ N/2,
	// ordered in bit-reversed order.
	wNjInv []complex128
	// w2Nj holds the precomputed values of w_2N^j where j = 0 ~ N/2.
	w2Nj []complex128
	// w2NjInv holds the precomputed values of scaled w_2N^-j / (N / 2) where j = 0 ~ N/2.
	w2NjInv []complex128

	buffer fourierBuffer[T]
}

// fourierBuffer contains buffer values for FourierTransformer.
type fourierBuffer[T num.Integer] struct {
	// fp holds the FFT value of p.
	fp FourierPoly
	// fpInv holds the InvFFT value of fp.
	fpInv FourierPoly
}

// NewFourierTransformer creates a new FourierTransformer with degree N.
// N should be power of two.
func NewFourierTransformer[T num.Integer](N int) *FourierTransformer[T] {
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

	return &FourierTransformer[T]{
		degree: N,
		maxT:   math.Exp2(float64(num.SizeT[T]())),

		wNj:     wNj,
		wNjInv:  wNjInv,
		w2Nj:    w2Nj,
		w2NjInv: w2NjInv,

		buffer: newFourierBuffer[T](N),
	}
}

// newFourierBuffer allocates an empty fourierBuffer.
func newFourierBuffer[T num.Integer](N int) fourierBuffer[T] {
	return fourierBuffer[T]{
		fp:    NewFourierPoly(N),
		fpInv: NewFourierPoly(N),
	}
}

// ShallowCopy returns a shallow copy of this FourierTransformer.
// Returned FourierTransformer is safe for concurrent use.
func (f *FourierTransformer[T]) ShallowCopy() *FourierTransformer[T] {
	return &FourierTransformer[T]{
		degree: f.degree,
		maxT:   f.maxT,

		wNj:     f.wNj,
		wNjInv:  f.wNjInv,
		w2Nj:    f.w2Nj,
		w2NjInv: f.w2NjInv,

		buffer: newFourierBuffer[T](f.degree),
	}
}

// FFTInPlace applies FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierTransformer[T]) FFTInPlace(fp FourierPoly) {
	fftInPlace(fp.Coeffs, f.wNj)
}

// fftInPlace is a top-level function for FFTInPlace.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs, wNj []complex128) {
	N := len(coeffs)

	// Implementation of Algorithm 1 from https://eprint.iacr.org/2016/504.pdf
	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := i * t << 1
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]*wNj[m+i]
				coeffs[j], coeffs[j+t] = U+V, U-V
			}
		}
	}
}

// InvFFTInPlace applies Inverse FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierTransformer[T]) InvFFTInPlace(fp FourierPoly) {
	invfftInPlace(fp.Coeffs, f.wNjInv)
}

// invfftInPlace is a top-level function for InvFFTInPlace.
// All internal inverse FFT implementations calls this function for performance.
func invfftInPlace(coeffs, wNjInv []complex128) {
	N := len(coeffs)

	// Implementation of Algorithm 2 from https://eprint.iacr.org/2016/504.pdf
	t := 1
	for m := N; m > 1; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t
			for j := j1; j < j2; j++ {
				U, V := coeffs[j], coeffs[j+t]
				coeffs[j], coeffs[j+t] = U+V, (U-V)*wNjInv[h+i]
			}
			j1 += t << 1
		}
		t <<= 1
	}
}

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (f *FourierTransformer[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fp)
	return fp
}

// ToFourierPolyAssign transforms Poly to FourierPoly.
func (f *FourierTransformer[T]) ToFourierPolyAssign(p Poly[T], fp FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int(p.Coeffs[j])), float64(int(-p.Coeffs[j+N/2]))) * f.w2Nj[j]
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int8(p.Coeffs[j])), float64(int8(-p.Coeffs[j+N/2]))) * f.w2Nj[j]
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int16(p.Coeffs[j])), float64(int16(-p.Coeffs[j+N/2]))) * f.w2Nj[j]
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int32(p.Coeffs[j])), float64(int32(-p.Coeffs[j+N/2]))) * f.w2Nj[j]
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int64(p.Coeffs[j])), float64(int64(-p.Coeffs[j+N/2]))) * f.w2Nj[j]
		}
	default:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(-p.Coeffs[j+N/2])) * f.w2Nj[j]
		}
	}

	fftInPlace(fp.Coeffs, f.wNj)
}

// ToScaledFourierPoly transforms Poly to FourierPoly and returns it.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierTransformer[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyAssign(p, fp)
	return fp
}

// ToScaledFourierPolyAssign transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierTransformer[T]) ToScaledFourierPolyAssign(p Poly[T], fp FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int(p.Coeffs[j]))/f.maxT, float64(int(-p.Coeffs[j+N/2]))/f.maxT) * f.w2Nj[j]
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int8(p.Coeffs[j]))/f.maxT, float64(int8(-p.Coeffs[j+N/2]))/f.maxT) * f.w2Nj[j]
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int16(p.Coeffs[j]))/f.maxT, float64(int16(-p.Coeffs[j+N/2]))/f.maxT) * f.w2Nj[j]
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int32(p.Coeffs[j]))/f.maxT, float64(int32(-p.Coeffs[j+N/2]))/f.maxT) * f.w2Nj[j]
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int64(p.Coeffs[j]))/f.maxT, float64(int64(-p.Coeffs[j+N/2]))/f.maxT) * f.w2Nj[j]
		}
	default:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(p.Coeffs[j])/f.maxT, float64(-p.Coeffs[j+N/2])/f.maxT) * f.w2Nj[j]
		}
	}

	fftInPlace(fp.Coeffs, f.wNj)
}

// scaleFloat64 scales x by 2^sizeT.
func (f *FourierTransformer[T]) scaleFloat64(x float64) float64 {
	return (x - math.Round(x)) * f.maxT
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
func (f *FourierTransformer[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToStandardPolyAssign(fp, p)
	return p
}

// ToStandardPolyAssign transforms FourierPoly to Poly.
func (f *FourierTransformer[T]) ToStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invfftInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int(real(c)))
			p.Coeffs[j+N/2] = -T(int(imag(c)))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int8(real(c)))
			p.Coeffs[j+N/2] = -T(int8(imag(c)))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int16(real(c)))
			p.Coeffs[j+N/2] = -T(int16(imag(c)))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int32(real(c)))
			p.Coeffs[j+N/2] = -T(int32(imag(c)))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int64(real(c)))
			p.Coeffs[j+N/2] = -T(int64(imag(c)))
		}
	default:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(real(c))
			p.Coeffs[j+N/2] = -T(imag(c))
		}
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly and returns it.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierTransformer[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, p)
	return p
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierTransformer[T]) ToScaledStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invfftInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] = -T(int(f.scaleFloat64(imag(c))))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int8(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] = -T(int8(f.scaleFloat64(imag(c))))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int16(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] = -T(int16(f.scaleFloat64(imag(c))))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int32(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] = -T(int32(f.scaleFloat64(imag(c))))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(int64(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] = -T(int64(f.scaleFloat64(imag(c))))
		}
	default:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] = T(f.scaleFloat64(real(c)))
			p.Coeffs[j+N/2] = -T(f.scaleFloat64(imag(c)))
		}
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierTransformer[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invfftInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(int(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] += -T(int(f.scaleFloat64(imag(c))))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(int8(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] += -T(int8(f.scaleFloat64(imag(c))))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(int16(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] += -T(int16(f.scaleFloat64(imag(c))))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(int32(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] += -T(int32(f.scaleFloat64(imag(c))))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(int64(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] += -T(int64(f.scaleFloat64(imag(c))))
		}
	default:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] += T(f.scaleFloat64(real(c)))
			p.Coeffs[j+N/2] += -T(f.scaleFloat64(imag(c)))
		}
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierTransformer[T]) ToScaledStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invfftInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(int(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] -= -T(int(f.scaleFloat64(imag(c))))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(int8(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] -= -T(int8(f.scaleFloat64(imag(c))))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(int16(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] -= -T(int16(f.scaleFloat64(imag(c))))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(int32(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] -= -T(int32(f.scaleFloat64(imag(c))))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(int64(f.scaleFloat64(real(c))))
			p.Coeffs[j+N/2] -= -T(int64(f.scaleFloat64(imag(c))))
		}
	default:
		for j := 0; j < N/2; j++ {
			c := f.buffer.fpInv.Coeffs[j] * f.w2NjInv[j]
			p.Coeffs[j] -= T(f.scaleFloat64(real(c)))
			p.Coeffs[j+N/2] -= -T(f.scaleFloat64(imag(c)))
		}
	}
}

// Add adds fp0, fp1 and returns the result.
func (f *FourierTransformer[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.AddAssign(fp0, fp1, fp)
	return fp
}

// AddAssign adds fp0, fp1 and writes it to fpOut.
func (f *FourierTransformer[T]) AddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.AddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Sub subtracts fp0, fp1 and returns the result.
func (f *FourierTransformer[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.SubAssign(fp0, fp1, fp)
	return fp
}

// SubAssign subtracts fp0, fp1 and writes it to fpOut.
func (f *FourierTransformer[T]) SubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.SubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Neg negates fp0 and returns the result.
func (f *FourierTransformer[T]) Neg(fp0 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.NegAssign(fp0, fp)
	return fp
}

// NegAssign negates fp0 and writes it to fpOut.
func (f *FourierTransformer[T]) NegAssign(fp0, fpOut FourierPoly) {
	vec.NegAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Mul multiplies fp0, fp1 and returns the result.
func (f *FourierTransformer[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulAssign(fp0, fp1, fp)
	return fp
}

// MulAssign multiplies fp0, fp1 and writes it to fpOut.
func (f *FourierTransformer[T]) MulAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddAssign multiplies fp0, fp1 and adds it to fpOut.
func (f *FourierTransformer[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f *FourierTransformer[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulSubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMul multiplies fp0, p1 and returns the result.
func (f *FourierTransformer[T]) PolyMul(fp0 FourierPoly, p1 Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.PolyMulAssign(fp0, p1, fp)
	return fp
}

// PolyMulAssign multiplies fp0, p1 and writes it to fpOut.
func (f *FourierTransformer[T]) PolyMulAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f *FourierTransformer[T]) PolyMulAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAddAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign multiplies fp0, p1 and subtracts it from fpOut.
func (f *FourierTransformer[T]) PolyMulSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulSubAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// ScalarMul multiplies c to fp0 and returns the result.
func (f *FourierTransformer[T]) ScalarMul(fp0 FourierPoly, c float64) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ScalarMulAssign(fp0, c, fp)
	return fp
}

// ScalarMulAssign multiplies c to fp0 and writes it to fpOut.
func (f *FourierTransformer[T]) ScalarMulAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	vec.ScalarMulAssign(fp0.Coeffs, complex(c, 0), fpOut.Coeffs)
}
