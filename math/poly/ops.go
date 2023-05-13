package poly

import (
	"github.com/sp301415/tfhe/math/vec"
)

// Add adds p0, p1 and returns the result.
func (e Evaluater[T]) Add(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.AddInPlace(p0, p1, p)
	return p
}

// AddInPlace adds p0, p1 and writes it to pOut.
func (e Evaluater[T]) AddInPlace(p0, p1, pOut Poly[T]) {
	vec.AddInPlace(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// AddAssign adds p0 to ptOut.
func (e Evaluater[T]) AddAssign(p0, pOut Poly[T]) {
	vec.AddAssign(p0.Coeffs, pOut.Coeffs)
}

// Sub subtracts p0, p1 and returns the result.
func (e Evaluater[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.SubInPlace(p0, p1, p)
	return p
}

// SubInPlace subtracts p0, p1 and writes it to pOut.
func (e Evaluater[T]) SubInPlace(p0, p1, pOut Poly[T]) {
	vec.SubInPlace(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// SubAssign subtracts p0 from pOut.
func (e Evaluater[T]) SubAssign(p0, pOut Poly[T]) {
	vec.SubAssign(p0.Coeffs, pOut.Coeffs)
}

// Neg negates p0 and returns the result.
func (e Evaluater[T]) Neg(p0 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.NegInPlace(p0, p)
	return p
}

// NegInPlace negates p0 and writes it to pOut.
func (e Evaluater[T]) NegInPlace(p0, pOut Poly[T]) {
	vec.NegInPlace(p0.Coeffs, pOut.Coeffs)
}

// NegAssign negates p0.
func (e Evaluater[T]) NegAssign(p0 Poly[T]) {
	vec.NegAssign(p0.Coeffs)
}

// Mul multiplies p0, p1 and returns the result.
func (e Evaluater[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.MulInPlace(p0, p1, p)
	return p
}

// MulInPlace multiplies p0, p1 and writes it to pOut.
func (e Evaluater[T]) MulInPlace(p0, p1, pOut Poly[T]) {
	if e.degree <= KaratsubaRecurseThreshold {
		e.mulInPlaceNaive(p0, p1, pOut)
	} else {
		e.mulInPlaceKaratsuba(p0, p1, pOut)
	}
}

// MulAssign multiplies p0 to pOut.
func (e Evaluater[T]) MulAssign(p0, pOut Poly[T]) {
	e.buffer.pOut.CopyFrom(pOut)
	if e.degree <= KaratsubaRecurseThreshold {
		e.mulInPlaceNaive(p0, e.buffer.pOut, pOut)
	} else {
		e.mulInPlaceKaratsuba(p0, e.buffer.pOut, pOut)
	}
}

// MulAddAssign multiplies p0, p1 and adds it to pOut.
func (e Evaluater[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.MulInPlace(p0, p1, e.buffer.pOut)
	e.AddAssign(e.buffer.pOut, pOut)
}

// MulSubAssign multiplies p0, p1 and subtracts it from pOut.
func (e Evaluater[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.MulInPlace(p0, p1, e.buffer.pOut)
	e.SubAssign(e.buffer.pOut, pOut)
}

// ScalarMul multplies c to p0 and returns the result.
func (e Evaluater[T]) ScalarMul(p0 Poly[T], c T) Poly[T] {
	p := New[T](e.degree)
	e.ScalarMulInPlace(p0, c, p)
	return p
}

// ScalarMulInPlace multplies c to p0 and writes it to pOut.
func (e Evaluater[T]) ScalarMulInPlace(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulInPlace(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulAssign multplies c to pOut.
func (e Evaluater[T]) ScalarMulAssign(c T, pOut Poly[T]) {
	vec.ScalarMulAssign(c, pOut.Coeffs)
}

// MonomialMul multplies X^d to p0 and returns the result.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMul(p0 Poly[T], d int) Poly[T] {
	p := New[T](e.degree)
	e.MonomialMulInPlace(p0, d, p)
	return p
}

// MonomialMulInPlace multplies X^d to p0 and writes it to pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulInPlace(p0 Poly[T], d int, pOut Poly[T]) {
	dd := d % e.degree
	vec.RotateInPlace(p0.Coeffs, dd, pOut.Coeffs)

	cycles := d / e.degree
	if cycles%2 != 0 {
		vec.NegAssign(pOut.Coeffs)
	}

	for i := 0; i < dd; i++ {
		pOut.Coeffs[i] = -pOut.Coeffs[i]
	}
}

// MonomialMulAssign multplies X^d to pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulAssign(d int, pOut Poly[T]) {
	dd := d % e.degree
	vec.RotateAssign(pOut.Coeffs, dd)

	cycles := d / e.degree
	if cycles%2 != 0 {
		vec.NegAssign(pOut.Coeffs)
	}

	for i := 0; i < dd; i++ {
		pOut.Coeffs[i] = -pOut.Coeffs[i]
	}
}

// MonomialMul divides X^d from p0 and returns the result.
// Panics if d < 0.
func (e Evaluater[T]) MonomialDiv(p0 Poly[T], d int) Poly[T] {
	p := New[T](e.degree)
	e.MonomialDivInPlace(p0, d, p)
	return p
}

// MonomialDivInPlace divides X^d from p0 and writes it to pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialDivInPlace(p0 Poly[T], d int, pOut Poly[T]) {
	dd := d % e.degree
	vec.RotateInPlace(p0.Coeffs, -dd, pOut.Coeffs)

	cycles := d / e.degree
	if cycles%2 != 0 {
		vec.NegAssign(pOut.Coeffs)
	}

	for i := e.degree - dd; i < e.degree; i++ {
		pOut.Coeffs[i] = -pOut.Coeffs[i]
	}
}

// MonomialMulAssign divides X^d from pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialDivAssign(d int, pOut Poly[T]) {
	dd := d % e.degree
	vec.RotateAssign(pOut.Coeffs, -dd)

	cycles := d / e.degree
	if cycles%2 != 0 {
		vec.NegAssign(pOut.Coeffs)
	}

	for i := e.degree - dd; i < e.degree; i++ {
		pOut.Coeffs[i] = -pOut.Coeffs[i]
	}
}
