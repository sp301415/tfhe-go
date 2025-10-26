package poly

import (
	"math/bits"

	"github.com/sp301415/tfhe-go/math/num"
)

// AddFFTPoly returns fp0 + fp1.
func (e *Evaluator[T]) AddFFTPoly(fp0, fp1 FFTPoly) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.AddFFTPolyTo(fpOut, fp0, fp1)
	return fpOut
}

// AddFFTPolyTo computes fpOut = fp0 + fp1.
func (e *Evaluator[T]) AddFFTPolyTo(fpOut, fp0, fp1 FFTPoly) {
	addCmplxTo(fpOut.Coeffs, fp0.Coeffs, fp1.Coeffs)
}

// SubFFTPoly returns fp0 - fp1.
func (e *Evaluator[T]) SubFFTPoly(fp0, fp1 FFTPoly) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.SubFFTPolyTo(fpOut, fp0, fp1)
	return fpOut
}

// SubFFTPolyTo computes fpOut = fp0 - fp1.
func (e *Evaluator[T]) SubFFTPolyTo(fpOut, fp0, fp1 FFTPoly) {
	subCmplxTo(fpOut.Coeffs, fp0.Coeffs, fp1.Coeffs)
}

// NegFFTPoly returns -fp.
func (e *Evaluator[T]) NegFFTPoly(fp FFTPoly) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.NegFFTPolyTo(fpOut, fp)
	return fpOut
}

// NegFFTPolyTo computes fpOut = -fp.
func (e *Evaluator[T]) NegFFTPolyTo(fpOut, fp FFTPoly) {
	negCmplxTo(fpOut.Coeffs, fp.Coeffs)
}

// FloatMulFFTPoly returns c * fp.
func (e *Evaluator[T]) FloatMulFFTPoly(fp FFTPoly, c float64) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.FloatMulFFTPolyTo(fpOut, fp, c)
	return fpOut
}

// FloatMulFFTPolyTo computes fpOut = c * fp.
func (e *Evaluator[T]) FloatMulFFTPolyTo(fpOut, fp FFTPoly, c float64) {
	floatMulCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// FloatMulAddFFTPolyTo computes fpOut += c * fp.
func (e *Evaluator[T]) FloatMulAddFFTPolyTo(fpOut, fp FFTPoly, c float64) {
	floatMulAddCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// FloatMulSubFFTPolyTo computes fpOut -= c * fp.
func (e *Evaluator[T]) FloatMulSubFFTPolyTo(fpOut, fp FFTPoly, c float64) {
	floatMulSubCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// CmplxMulFFTPoly returns c * fp.
func (e *Evaluator[T]) CmplxMulFFTPoly(fp FFTPoly, c complex128) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.CmplxMulFFTPolyTo(fpOut, fp, c)
	return fpOut
}

// CmplxMulFFTPolyTo computes fpOut = c * fp.
func (e *Evaluator[T]) CmplxMulFFTPolyTo(fpOut, fp FFTPoly, c complex128) {
	cmplxMulCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// CmplxMulAddFFTPolyTo computes fpOut += c * fp.
func (e *Evaluator[T]) CmplxMulAddFFTPolyTo(fpOut, fp FFTPoly, c complex128) {
	cmplxMulAddCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// CmplxMulSubFFTPolyTo computes fpOut -= c * fp.
func (e *Evaluator[T]) CmplxMulSubFFTPolyTo(fpOut, fp FFTPoly, c complex128) {
	cmplxMulSubCmplxTo(fpOut.Coeffs, fp.Coeffs, c)
}

// MulFFTPoly returns fp0 * fp1.
func (e *Evaluator[T]) MulFFTPoly(fp0, fp1 FFTPoly) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.MulFFTPolyTo(fpOut, fp0, fp1)
	return fpOut
}

// MulFFTPolyTo computes fpOut = fp0 * fp1.
func (e *Evaluator[T]) MulFFTPolyTo(fpOut, fp0, fp1 FFTPoly) {
	mulCmplxTo(fpOut.Coeffs, fp0.Coeffs, fp1.Coeffs)
}

// MulAddFFTPolyTo computes fpOut += fp0 * fp1.
func (e *Evaluator[T]) MulAddFFTPolyTo(fpOut, fp0, fp1 FFTPoly) {
	mulAddCmplxTo(fpOut.Coeffs, fp0.Coeffs, fp1.Coeffs)
}

// MulSubFFTPolyTo computes fpOut -= fp0 * fp1.
func (e *Evaluator[T]) MulSubFFTPolyTo(fpOut, fp0, fp1 FFTPoly) {
	mulSubCmplxTo(fpOut.Coeffs, fp0.Coeffs, fp1.Coeffs)
}

// PolyMulFFTPoly returns p * fp as FFTPoly.
func (e *Evaluator[T]) PolyMulFFTPoly(fp FFTPoly, p Poly[T]) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.PolyMulFFTPolyTo(fpOut, fp, p)
	return fpOut
}

// PolyMulFFTPolyTo computes fpOut = p * fp.
func (e *Evaluator[T]) PolyMulFFTPolyTo(fpOut, fp FFTPoly, p Poly[T]) {
	e.FFTTo(e.buf.fp, p)
	mulCmplxTo(fpOut.Coeffs, fp.Coeffs, e.buf.fp.Coeffs)
}

// PolyMulAddFFTPolyTo computes fpOut += p * fp.
func (e *Evaluator[T]) PolyMulAddFFTPolyTo(fpOut, fp FFTPoly, p Poly[T]) {
	e.FFTTo(e.buf.fp, p)
	mulAddCmplxTo(fpOut.Coeffs, fp.Coeffs, e.buf.fp.Coeffs)
}

// PolyMulSubFFTPolyTo computes fpOut -= p * fp.
func (e *Evaluator[T]) PolyMulSubFFTPolyTo(fpOut, fp FFTPoly, p Poly[T]) {
	e.FFTTo(e.buf.fp, p)
	mulSubCmplxTo(fpOut.Coeffs, fp.Coeffs, e.buf.fp.Coeffs)
}

// PermuteFFTPoly returns fp(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTPoly(fp FFTPoly, d int) FFTPoly {
	fpOut := e.NewFFTPoly()
	e.PermuteFFTPolyTo(fpOut, fp, d)
	return fpOut
}

// PermuteFFTPolyTo computes fpOut = fp(X^d).
//
// fp and fpOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteFFTPolyInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTPolyTo(fpOut, fp FFTPoly, d int) {
	if d&1 == 0 {
		panic("PermuteFFTPolyTo: d not odd")
	}

	revShiftBits := 64 - (num.Log2(e.rank) - 1)

	d = d & (2*e.rank - 1)
	if d%4 == 1 {
		k := (d - 1) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) | (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (d*ci - k) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) | (cj & 3)

				fpOut.Coeffs[i+0] = fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] = fp.Coeffs[j+4]
			}
		}
	} else {
		k := (d - 3) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) | (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (-d*ci + k + 1) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) | (cj & 3)

				fpOut.Coeffs[i+0] = fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] = -fp.Coeffs[j+4]
			}
		}
	}
}

// PermuteFFTPolyInPlace computes fp = fp(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTPolyInPlace(fp FFTPoly, d int) {
	if d&1 == 0 {
		panic("PermuteFFTPolyInPlace: d not odd")
	}

	e.PermuteFFTPolyTo(e.buf.fpOut, fp, d)
	fp.CopyFrom(e.buf.fpOut)
}

// PermuteAddFFTPolyTo computes fpOut += fp(X^d).
//
// fp and fpOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddFFTPolyTo(fpOut, fp FFTPoly, d int) {
	if d&1 == 0 {
		panic("PermuteAddFFTPolyTo: d not odd")
	}

	d = d & (2*e.rank - 1)
	revShiftBits := 64 - (num.Log2(e.rank) - 1)
	if d%4 == 1 {
		k := (d - 1) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) + (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (d*ci - k) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) + (cj & 3)

				fpOut.Coeffs[i+0] += fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] += fp.Coeffs[j+4]
			}
		}
	} else {
		k := (d - 3) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) + (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (-d*ci + k + 1) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) + (cj & 3)

				fpOut.Coeffs[i+0] += fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] += -fp.Coeffs[j+4]
			}
		}
	}
}

// PermuteSubFFTPolyTo computes fpOut -= fp(X^d).
//
// fp and fpOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubFFTPolyTo(fpOut, fp FFTPoly, d int) {
	if d&1 == 0 {
		panic("PermuteSubFFTPolyTo: d not odd")
	}

	d = d & (2*e.rank - 1)
	revShiftBits := 64 - (num.Log2(e.rank) - 1)
	if d%4 == 1 {
		k := (d - 1) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) | (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (d*ci - k) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) | (cj & 3)

				fpOut.Coeffs[i+0] -= fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] -= fp.Coeffs[j+4]
			}
		}
	} else {
		k := (d - 3) >> 2
		var ci, cj int
		for ii := 0; ii < e.rank; ii += 8 {
			for i := ii; i < ii+4; i++ {
				ci = ((i >> 3) << 2) | (i & 3)
				ci = int(bits.Reverse64(uint64(ci)) >> revShiftBits)
				cj = (-d*ci + k + 1) & (e.rank>>1 - 1)
				cj = int(bits.Reverse64(uint64(cj)) >> revShiftBits)
				j := ((cj >> 2) << 3) | (cj & 3)

				fpOut.Coeffs[i+0] -= fp.Coeffs[j+0]
				fpOut.Coeffs[i+4] -= -fp.Coeffs[j+4]
			}
		}
	}
}
