package poly

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// Add returns p0 + p1.
func (e *Evaluator[T]) Add(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.AddAssign(p0, p1, pOut)
	return pOut
}

// AddAssign computes pOut = p0 + p1.
func (e *Evaluator[T]) AddAssign(p0, p1, pOut Poly[T]) {
	vec.AddAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Sub returns p0 - p1.
func (e *Evaluator[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.SubAssign(p0, p1, pOut)
	return pOut
}

// SubAssign computes pOut = p0 - p1.
func (e *Evaluator[T]) SubAssign(p0, p1, pOut Poly[T]) {
	vec.SubAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Neg returns pOut = -p0.
func (e *Evaluator[T]) Neg(p0 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.NegAssign(p0, pOut)
	return pOut
}

// NegAssign computes pOut = -p0.
func (e *Evaluator[T]) NegAssign(p0, pOut Poly[T]) {
	vec.NegAssign(p0.Coeffs, pOut.Coeffs)
}

// ScalarMul returns c * p0.
func (e *Evaluator[T]) ScalarMul(p0 Poly[T], c T) Poly[T] {
	pOut := e.NewPoly()
	e.ScalarMulAssign(p0, c, pOut)
	return pOut
}

// ScalarMulAssign computes pOut = c * p0.
func (e *Evaluator[T]) ScalarMulAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulAddAssign computes pOut += c * p0.
func (e *Evaluator[T]) ScalarMulAddAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAddAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulSubAssign computes pOut -= c * p0.
func (e *Evaluator[T]) ScalarMulSubAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulSubAssign(p0.Coeffs, c, pOut.Coeffs)
}

// Mul returns p0 * p1.
func (e *Evaluator[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	if e.degree <= karatsubaRecurseThreshold {
		return e.mulNaive(p0, p1)
	}

	pOut := e.NewPoly()
	e.mulKaratsubaAssign(p0, p1, pOut)
	return pOut
}

// MulAssign computes pOut = p0 * p1.
func (e *Evaluator[T]) MulAssign(p0, p1, pOut Poly[T]) {
	if e.degree <= karatsubaRecurseThreshold {
		e.mulNaiveAssign(p0, p1, pOut)
	} else {
		e.mulKaratsubaAssign(p0, p1, pOut)
	}
}

// MulAddAssign computes pOut += p0 * p1.
func (e *Evaluator[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.AddAssign(pOut, e.buffer.pOut, pOut)
}

// MulSubAssign computes pOut -= p0 * p1.
func (e *Evaluator[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.SubAssign(pOut, e.buffer.pOut, pOut)
}

// MonomialMul returns X^d * p0.
func (e *Evaluator[T]) MonomialMul(p0 Poly[T], d int) Poly[T] {
	pOut := e.NewPoly()
	e.MonomialMulAssign(p0, d, pOut)
	return pOut
}

// MonomialMulAssign computes pOut = X^d * p0.
//
// p0 and pOut should not overlap. For inplace multiplication,
// use [*Evaluator.MonomialMulInPlace].
func (e *Evaluator[T]) MonomialMulAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d & (2*e.degree - 1); {
	case e.degree <= k:
		for i, ii := 0, -k+2*e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii]
		}
		for i, ii := k-e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii]
		}
	case 0 <= k && k < e.degree:
		for i, ii := 0, -k+e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii]
		}
	case -e.degree <= k && k < 0:
		for i, ii := 0, -k; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii]
		}
		for i, ii := k+e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii]
		}
	case k < -e.degree:
		for i, ii := 0, -k-e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii]
		}
		for i, ii := k+2*e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii]
		}
	}
}

// MonomialMulInPlace computes p0 = X^d * p0.
func (e *Evaluator[T]) MonomialMulInPlace(p0 Poly[T], d int) {
	kk := d & (e.degree - 1)
	vec.RotateInPlace(p0.Coeffs, kk)

	switch k := d & (2*e.degree - 1); {
	case e.degree <= k:
		for i := kk; i < e.degree; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < kk; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case -e.degree <= k && k < 0:
		for i := e.degree + kk; i < e.degree; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case k < -e.degree:
		for i := 0; i < e.degree+kk; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	}
}

// MonomialMulAddAssign computes pOut += X^d * p0.
//
// p0 and pOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d & (2*e.degree - 1); {
	case e.degree <= k:
		for i, ii := 0, -k+2*e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii]
		}
		for i, ii := k-e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii]
		}
	case 0 <= k && k < e.degree:
		for i, ii := 0, -k+e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii]
		}
	case -e.degree <= k && k < 0:
		for i, ii := 0, -k; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii]
		}
		for i, ii := k+e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii]
		}
	case k < -e.degree:
		for i, ii := 0, -k-e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii]
		}
		for i, ii := k+2*e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii]
		}
	}
}

// MonomialMulSubAssign computes pOut -= X^d * p0.
//
// p0 and pOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d & (2*e.degree - 1); {
	case e.degree <= k:
		for i, ii := 0, -k+2*e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p0.Coeffs[ii]
		}
		for i, ii := k-e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p0.Coeffs[ii]
		}
	case 0 <= k && k < e.degree:
		for i, ii := 0, -k+e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p0.Coeffs[ii]
		}
		for i, ii := k, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p0.Coeffs[ii]
		}
	case -e.degree <= k && k < 0:
		for i, ii := 0, -k; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p0.Coeffs[ii]
		}
		for i, ii := k+e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p0.Coeffs[ii]
		}
	case k < -e.degree:
		for i, ii := 0, -k-e.degree; ii < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= -p0.Coeffs[ii]
		}
		for i, ii := k+2*e.degree, 0; i < e.degree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] -= p0.Coeffs[ii]
		}
	}
}

// MonomialMulSubOneMulAssign computes pOut = (X^d - 1) * p0.
//
// d should be positive, and p0 and pOut should not overlap.
func (e *Evaluator[T]) MonomialSubOneMulAssign(p0 Poly[T], d int, pOut Poly[T]) {
	monomialSubOneMulAssign(p0, d&(2*e.degree-1), pOut)
}

// MonomialMulSubOneMulAddAssign computes pOut += (X^d - 1) * p0.
//
// d should be positive, and p0 and pOut should not overlap.
func (e *Evaluator[T]) MonomialSubOneMulAddAssign(p0 Poly[T], d int, pOut Poly[T]) {
	monomialSubOneMulAddAssign(p0, d&(2*e.degree-1), pOut)
}
