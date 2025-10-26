package poly

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// AddPoly returns p0 + p1.
func (e *Evaluator[T]) AddPoly(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.AddPolyTo(pOut, p0, p1)
	return pOut
}

// AddPolyTo computes pOut = p0 + p1.
func (e *Evaluator[T]) AddPolyTo(pOut, p0, p1 Poly[T]) {
	vec.AddTo(pOut.Coeffs, p0.Coeffs, p1.Coeffs)
}

// SubPoly returns p0 - p1.
func (e *Evaluator[T]) SubPoly(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.SubPolyTo(pOut, p0, p1)
	return pOut
}

// SubPolyTo computes pOut = p0 - p1.
func (e *Evaluator[T]) SubPolyTo(pOut, p0, p1 Poly[T]) {
	vec.SubTo(pOut.Coeffs, p0.Coeffs, p1.Coeffs)
}

// NegPoly returns pOut = -p0.
func (e *Evaluator[T]) NegPoly(p0 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.NegPolyTo(pOut, p0)
	return pOut
}

// NegPolyTo computes pOut = -p.
func (e *Evaluator[T]) NegPolyTo(pOut, p Poly[T]) {
	vec.NegTo(pOut.Coeffs, p.Coeffs)
}

// ScalarMulPoly returns c * p.
func (e *Evaluator[T]) ScalarMulPoly(p Poly[T], c T) Poly[T] {
	pOut := e.NewPoly()
	e.ScalarMulPolyTo(pOut, p, c)
	return pOut
}

// ScalarMulPolyTo computes pOut = c * p.
func (e *Evaluator[T]) ScalarMulPolyTo(pOut, p Poly[T], c T) {
	vec.ScalarMulTo(pOut.Coeffs, p.Coeffs, c)
}

// ScalarMulAddPolyTo computes pOut += c * p.
func (e *Evaluator[T]) ScalarMulAddPolyTo(pOut, p Poly[T], c T) {
	vec.ScalarMulAddTo(pOut.Coeffs, p.Coeffs, c)
}

// ScalarMulSubPolyTo computes pOut -= c * p.
func (e *Evaluator[T]) ScalarMulSubPolyTo(pOut, p Poly[T], c T) {
	vec.ScalarMulSubTo(pOut.Coeffs, p.Coeffs, c)
}

// FFTPolyMulPoly returns fp * p.
func (e *Evaluator[T]) FFTPolyMulPoly(p Poly[T], fp FFTPoly) Poly[T] {
	pOut := e.NewPoly()
	e.FFTPolyMulPolyTo(pOut, p, fp)
	return pOut
}

// FFTPolyMulPolyTo computes pOut = fp * p.
func (e *Evaluator[T]) FFTPolyMulPolyTo(pOut, p Poly[T], fp FFTPoly) {
	e.FFTTo(e.buf.fp, p)
	e.MulFFTPolyTo(e.buf.fp, e.buf.fp, fp)
	e.InvFFTToUnsafe(pOut, e.buf.fp)
}

// FFTPolyMulAddPolyTo computes pOut += fp * p.
func (e *Evaluator[T]) FFTPolyMulAddPolyTo(pOut, p Poly[T], fp FFTPoly) {
	e.FFTTo(e.buf.fp, p)
	e.MulFFTPolyTo(e.buf.fp, e.buf.fp, fp)
	e.InvFFTAddToUnsafe(pOut, e.buf.fp)
}

// FFTPolyMulSubPolyTo computes pOut -= fp * p.
func (e *Evaluator[T]) FFTPolyMulSubPolyTo(pOut, p Poly[T], fp FFTPoly) {
	e.FFTTo(e.buf.fp, p)
	e.MulFFTPolyTo(e.buf.fp, e.buf.fp, fp)
	e.InvFFTSubToUnsafe(pOut, e.buf.fp)
}

// MonomialMulPoly returns X^d * p.
func (e *Evaluator[T]) MonomialMulPoly(p Poly[T], d int) Poly[T] {
	pOut := e.NewPoly()
	e.MonomialMulPolyTo(pOut, p, d)
	return pOut
}

// MonomialMulPolyTo computes pOut = X^d * p.
//
// p0 and pOut should not overlap. For inplace multiplication,
// use [*Evaluator.MonomialMulPolyInPlace].
func (e *Evaluator[T]) MonomialMulPolyTo(pOut, p Poly[T], d int) {
	switch k := d & (2*e.rank - 1); {
	case e.rank <= k:
		for i, ii := 0, -k+2*e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p.Coeffs[ii]
		}
		for i, ii := k-e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p.Coeffs[ii]
		}
	case 0 <= k && k < e.rank:
		for i, ii := 0, -k+e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p.Coeffs[ii]
		}
	case -e.rank <= k && k < 0:
		for i, ii := 0, -k; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p.Coeffs[ii]
		}
		for i, ii := k+e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p.Coeffs[ii]
		}
	case k < -e.rank:
		for i, ii := 0, -k-e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p.Coeffs[ii]
		}
		for i, ii := k+2*e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p.Coeffs[ii]
		}
	}
}

// MonomialMulPolyInPlace computes p = X^d * p.
func (e *Evaluator[T]) MonomialMulPolyInPlace(p Poly[T], d int) {
	kk := d & (e.rank - 1)
	vec.RotateInPlace(p.Coeffs, kk)

	switch k := d & (2*e.rank - 1); {
	case e.rank <= k:
		for i := kk; i < e.rank; i++ {
			p.Coeffs[i] = -p.Coeffs[i]
		}
	case 0 <= k && k < e.rank:
		for i := 0; i < kk; i++ {
			p.Coeffs[i] = -p.Coeffs[i]
		}
	case -e.rank <= k && k < 0:
		for i := e.rank + kk; i < e.rank; i++ {
			p.Coeffs[i] = -p.Coeffs[i]
		}
	case k < -e.rank:
		for i := 0; i < e.rank+kk; i++ {
			p.Coeffs[i] = -p.Coeffs[i]
		}
	}
}

// MonomialMulAddPolyTo computes pOut += X^d * p.
//
// p and pOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddPolyTo(pOut, p Poly[T], d int) {
	switch k := d & (2*e.rank - 1); {
	case e.rank <= k:
		for i, ii := 0, -k+2*e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p.Coeffs[ii]
		}
		for i, ii := k-e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p.Coeffs[ii]
		}
	case 0 <= k && k < e.rank:
		for i, ii := 0, -k+e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p.Coeffs[ii]
		}
	case -e.rank <= k && k < 0:
		for i, ii := 0, -k; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p.Coeffs[ii]
		}
		for i, ii := k+e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p.Coeffs[ii]
		}
	case k < -e.rank:
		for i, ii := 0, -k-e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p.Coeffs[ii]
		}
		for i, ii := k+2*e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p.Coeffs[ii]
		}
	}
}

// MonomialMulSubPolyTo computes pOut -= X^d * p.
//
// p and pOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubPolyTo(pOut, p Poly[T], d int) {
	switch k := d & (2*e.rank - 1); {
	case e.rank <= k:
		for i, ii := 0, -k+2*e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p.Coeffs[ii]
		}
		for i, ii := k-e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p.Coeffs[ii]
		}
	case 0 <= k && k < e.rank:
		for i, ii := 0, -k+e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p.Coeffs[ii]
		}
	case -e.rank <= k && k < 0:
		for i, ii := 0, -k; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p.Coeffs[ii]
		}
		for i, ii := k+e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p.Coeffs[ii]
		}
	case k < -e.rank:
		for i, ii := 0, -k-e.rank; ii < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p.Coeffs[ii]
		}
		for i, ii := k+2*e.rank, 0; i < e.rank; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p.Coeffs[ii]
		}
	}
}

// PermutePoly returns p(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermutePoly(p Poly[T], d int) Poly[T] {
	pOut := e.NewPoly()
	e.PermutePolyTo(pOut, p, d)
	return pOut
}

// PermutePolyTo computes pOut = p(X^d).
//
// p0 and pOut should not overlap. For inplace permutation,
// use [*Evaluator.PermutePolyInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermutePolyTo(pOut, p Poly[T], d int) {
	if d&1 == 0 {
		panic("PermuteTo: d not odd")
	}

	for i := 0; i < e.rank; i++ {
		j := (d * i) & (2*e.rank - 1)
		if j < e.rank {
			pOut.Coeffs[j] = p.Coeffs[i]
		} else {
			pOut.Coeffs[j-e.rank] = -p.Coeffs[i]
		}
	}
}

// PermutePolyInPlace computes p = p(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermutePolyInPlace(p Poly[T], d int) {
	e.PermutePolyTo(e.buf.pOut, p, d)
	p.CopyFrom(e.buf.pOut)
}

// PermuteAddPolyTo computes pOut += p(X^d).
//
// p and pOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddPolyTo(pOut, p Poly[T], d int) {
	if d&1 == 0 {
		panic("PermuteAddTo: d not odd")
	}

	for i := 0; i < e.rank; i++ {
		j := (d * i) & (2*e.rank - 1)
		if j < e.rank {
			pOut.Coeffs[j] += p.Coeffs[i]
		} else {
			pOut.Coeffs[j-e.rank] -= p.Coeffs[i]
		}
	}
}

// PermuteSubPolyTo computes pOut -= p(X^d).
//
// p and pOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubPolyTo(pOut, p Poly[T], d int) {
	if d&1 == 0 {
		panic("PermuteSubTo: d not odd")
	}

	for i := 0; i < e.rank; i++ {
		j := (d * i) & (2*e.rank - 1)
		if j < e.rank {
			pOut.Coeffs[j] -= p.Coeffs[i]
		} else {
			pOut.Coeffs[j-e.rank] += p.Coeffs[i]
		}
	}
}
