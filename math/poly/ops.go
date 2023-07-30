package poly

import (
	"github.com/sp301415/tfhe/math/vec"
)

// Add adds p0, p1 and returns the result.
func (e Evaluator[T]) Add(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.AddAssign(p0, p1, p)
	return p
}

// AddAssign adds p0, p1 and writes it to pOut.
func (e Evaluator[T]) AddAssign(p0, p1, pOut Poly[T]) {
	vec.AddAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Sub subtracts p0, p1 and returns the result.
func (e Evaluator[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.SubAssign(p0, p1, p)
	return p
}

// SubAssign subtracts p0, p1 and writes it to pOut.
func (e Evaluator[T]) SubAssign(p0, p1, pOut Poly[T]) {
	vec.SubAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Neg negates p0 and returns the result.
func (e Evaluator[T]) Neg(p0 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.NegAssign(p0, p)
	return p
}

// NegAssign negates p0 and writes it to pOut.
func (e Evaluator[T]) NegAssign(p0, pOut Poly[T]) {
	vec.NegAssign(p0.Coeffs, pOut.Coeffs)
}

// Mul multiplies p0, p1 and returns the result.
func (e Evaluator[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.MulAssign(p0, p1, p)
	return p
}

// MulAssign multiplies p0, p1 and writes it to pOut.
func (e Evaluator[T]) MulAssign(p0, p1, pOut Poly[T]) {
	if e.degree <= karatsubaRecurseThreshold {
		e.mulAssignNaive(p0, p1, pOut)
	} else {
		e.mulAssignKaratsuba(p0, p1, pOut)
	}
}

// MulAddAssign multiplies p0, p1 and adds it to pOut.
func (e Evaluator[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.AddAssign(pOut, e.buffer.pOut, pOut)
}

// MulSubAssign multiplies p0, p1 and subtracts it from pOut.
func (e Evaluator[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.SubAssign(pOut, e.buffer.pOut, pOut)
}

// ScalarMul multplies c to p0 and returns the result.
func (e Evaluator[T]) ScalarMul(p0 Poly[T], c T) Poly[T] {
	p := New[T](e.degree)
	e.ScalarMulAssign(p0, c, p)
	return p
}

// ScalarMulAssign multplies c to p0 and writes it to pOut.
func (e Evaluator[T]) ScalarMulAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulAddAssign multplies c to p0 and adds it to pOut.
func (e Evaluator[T]) ScalarMulAddAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAddAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulSubAssign multplies c to p0 and subtracts it from pOut.
func (e Evaluator[T]) ScalarMulSubAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulSubAssign(p0.Coeffs, c, pOut.Coeffs)
}

// MonomialMul multplies X^d to p0 and returns the result.
func (e Evaluator[T]) MonomialMul(p0 Poly[T], d int) Poly[T] {
	p := New[T](e.degree)
	e.MonomialMulAssign(p0, d, p)
	return p
}

// MonomialMulAssign multplies X^d to p0 and writes it to pOut.
func (e Evaluator[T]) MonomialMulAssign(p0 Poly[T], d int, pOut Poly[T]) {
	dd := d % e.degree
	vec.RotateAssign(p0.Coeffs, dd, pOut.Coeffs)

	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		for i := dd; i < e.degree; i++ {
			pOut.Coeffs[i] = -pOut.Coeffs[i]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < dd; i++ {
			pOut.Coeffs[i] = -pOut.Coeffs[i]
		}
	case -e.degree <= k && k < 0:
		for i := e.degree + dd; i < e.degree; i++ {
			pOut.Coeffs[i] = -pOut.Coeffs[i]
		}
	case k < -e.degree:
		for i := 0; i < e.degree+dd; i++ {
			pOut.Coeffs[i] = -pOut.Coeffs[i]
		}
	}
}

// MonomialMulInPlace multplies X^d to p0.
func (e Evaluator[T]) MonomialMulInPlace(p0 Poly[T], d int) {
	dd := d % e.degree
	vec.RotateInPlace(p0.Coeffs, dd)

	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		for i := dd; i < e.degree; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < dd; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case -e.degree <= k && k < 0:
		for i := e.degree + dd; i < e.degree; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	case k < -e.degree:
		for i := 0; i < e.degree+dd; i++ {
			p0.Coeffs[i] = -p0.Coeffs[i]
		}
	}
}
