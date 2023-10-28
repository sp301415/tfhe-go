package poly

import (
	"math"

	"github.com/sp301415/tfhe-go/math/poly/internal/asm"
)

// FFTInPlace applies FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierEvaluator[T]) FFTInPlace(fp FourierPoly) {
	asm.FFTInPlace(fp.Coeffs, f.wNj)
}

// InvFFTInPlace applies Inverse FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierEvaluator[T]) InvFFTInPlace(fp FourierPoly) {
	asm.InvFFTInPlace(fp.Coeffs, f.wNjInv)
}

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (f *FourierEvaluator[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fp)
	return fp
}

// ToFourierPolyAssign transforms Poly to FourierPoly.
func (f *FourierEvaluator[T]) ToFourierPolyAssign(p Poly[T], fp FourierPoly) {
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

	asm.FFTInPlace(fp.Coeffs, f.wNj)
}

// ToScaledFourierPoly transforms Poly to FourierPoly and returns it.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyAssign(p, fp)
	return fp
}

// ToScaledFourierPolyAssign transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledFourierPolyAssign(p Poly[T], fp FourierPoly) {
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

	asm.FFTInPlace(fp.Coeffs, f.wNj)
}

// scaleFloat64 scales x by 2^sizeT.
func (f *FourierEvaluator[T]) scaleFloat64(x float64) float64 {
	return (x - math.Round(x)) * f.maxT
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
func (f *FourierEvaluator[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToStandardPolyAssign(fp, p)
	return p
}

// ToStandardPolyAssign transforms FourierPoly to Poly.
func (f *FourierEvaluator[T]) ToStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	asm.InvFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

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
func (f *FourierEvaluator[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, p)
	return p
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	asm.InvFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(int(c0))
			p.Coeffs[j+N/2] = -T(int(c1))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(int8(c0))
			p.Coeffs[j+N/2] = -T(int8(c1))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(int16(c0))
			p.Coeffs[j+N/2] = -T(int16(c1))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(int32(c0))
			p.Coeffs[j+N/2] = -T(int32(c1))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(int64(c0))
			p.Coeffs[j+N/2] = -T(int64(c1))
		}
	default:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] = T(c0)
			p.Coeffs[j+N/2] = -T(c1)
		}
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	asm.InvFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(int(c0))
			p.Coeffs[j+N/2] += -T(int(c1))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(int8(c0))
			p.Coeffs[j+N/2] += -T(int8(c1))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(int16(c0))
			p.Coeffs[j+N/2] += -T(int16(c1))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(int32(c0))
			p.Coeffs[j+N/2] += -T(int32(c1))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(int64(c0))
			p.Coeffs[j+N/2] += -T(int64(c1))
		}
	default:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] += T(c0)
			p.Coeffs[j+N/2] += -T(c1)
		}
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	asm.InvFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(int(c0))
			p.Coeffs[j+N/2] -= -T(int(c1))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(int8(c0))
			p.Coeffs[j+N/2] -= -T(int8(c1))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(int16(c0))
			p.Coeffs[j+N/2] -= -T(int16(c1))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(int32(c0))
			p.Coeffs[j+N/2] -= -T(int32(c1))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(int64(c0))
			p.Coeffs[j+N/2] -= -T(int64(c1))
		}
	default:
		for j := 0; j < N/2; j++ {
			c0, c1 := asm.MulAndScale(f.buffer.fpInv.Coeffs[j], f.w2NjInv[j], f.maxT)
			p.Coeffs[j] -= T(c0)
			p.Coeffs[j+N/2] -= -T(c1)
		}
	}
}
