package poly

import (
	"github.com/sp301415/tfhe/math/num"
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
	e.ToFourierPolyInPlace(p0, e.buffer.fp0)
	e.ToFourierPolyInPlace(p1, e.buffer.fp1)

	vec.ElementWiseMulInPlace(e.buffer.fp0.Coeffs, e.buffer.fp1.Coeffs, e.buffer.fpOut.Coeffs)

	e.ToStandardPolyInPlace(e.buffer.fpOut, pOut)
}

// MulAssign multiplies p0 to pOut.
func (e Evaluater[T]) MulAssign(p0, pOut Poly[T]) {
	e.ToFourierPolyInPlace(p0, e.buffer.fp0)
	e.ToFourierPolyInPlace(pOut, e.buffer.fpOut)

	vec.ElementWiseMulAssign(e.buffer.fp0.Coeffs, e.buffer.fpOut.Coeffs)

	e.ToStandardPolyInPlace(e.buffer.fpOut, pOut)
}

// MulAddAssign multiplies p0, p1 and adds to pOut.
func (e Evaluater[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.ToFourierPolyInPlace(p0, e.buffer.fp0)
	e.ToFourierPolyInPlace(p1, e.buffer.fp1)

	vec.ElementWiseMulInPlace(e.buffer.fp0.Coeffs, e.buffer.fp1.Coeffs, e.buffer.fpOut.Coeffs)

	e.toStandardPolyAddInPlace(e.buffer.fpOut, pOut)
}

// MulSubAssign multiplies p0, p1 and subtracts from pOut.
func (e Evaluater[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.ToFourierPolyInPlace(p0, e.buffer.fp0)
	e.ToFourierPolyInPlace(p1, e.buffer.fp1)

	vec.ElementWiseMulInPlace(e.buffer.fp0.Coeffs, e.buffer.fp1.Coeffs, e.buffer.fpOut.Coeffs)

	e.toStandardPolySubInPlace(e.buffer.fpOut, pOut)
}

// MulFourier multiplies fp0, fp1 and returns the result.
func (e Evaluater[T]) MulFourier(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(e.degree)
	e.MulFourierInPlace(fp0, fp1, fp)
	return fp
}

// MulFourierInPlace multiplies fp0, fp1 and writes it to fpOut.
func (e Evaluater[T]) MulFourierInPlace(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulInPlace(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulFourierAssign multiplies fp0 to fpOut.
func (e Evaluater[T]) MulFourierAssign(fp0, fpOut FourierPoly) {
	vec.ElementWiseMulAssign(fp0.Coeffs, fpOut.Coeffs)
}

// MulAddFourierAssign multiplies fp0, fp1 and adds to fpOut.
func (e Evaluater[T]) MulAddFourierAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubFourierAssign multiplies fp0, fp1 and subtracts from fpOut.
func (e Evaluater[T]) MulSubFourierAssign(fp0, fp1, fpOut Poly[T]) {
	vec.ElementWiseMulSubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
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

// ScalarDiv divides c from p0 and returns the result.
func (e Evaluater[T]) ScalarDiv(p0 Poly[T], c T) Poly[T] {
	p := New[T](e.degree)
	e.ScalarDivInPlace(p0, c, p)
	return p
}

// ScalarDivInPlace divides c from p0 and writes it to pOut.
func (e Evaluater[T]) ScalarDivInPlace(p0 Poly[T], c T, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = num.RoundRatio(p0.Coeffs[i], c)
	}
}

// ScalarDivAssign divides c from pOut.
func (e Evaluater[T]) ScalarDivAssign(c T, pOut Poly[T]) {
	e.ScalarDivInPlace(pOut, c, pOut)
}

// MonomialMul multplies c*x^d to p0 and returns the result.
// Panics if d < 0.
func (e Evaluater[T]) MonomialMul(p0 Poly[T], c T, d int) Poly[T] {
	p := New[T](e.degree)
	e.MonomialMulInPlace(p0, c, d, p)
	return p
}

// MonomialMulInPlace multplies c * X^d to p0 and writes it to pOut.
// Panics if d < 0.
func (e Evaluater[T]) MonomialMulInPlace(p0 Poly[T], c T, d int, pOut Poly[T]) {
	if d < 0 {
		panic("d smaller than zero")
	}

	// We can only consider d % 2*N, since X^2N = 1.
	d %= 2 * e.degree

	// If N <= d < 2N, X^d = X^N * X^(d-N) = -X^(d-N).
	if d >= e.degree {
		e.MonomialMulInPlace(p0, -c, d-e.degree, pOut)
		return
	}

	copy(pOut.Coeffs[d:], p0.Coeffs)
	copy(pOut.Coeffs[:d], p0.Coeffs[e.degree-d:])

	for i := 0; i < e.degree; i++ {
		if i < d {
			pOut.Coeffs[i] *= -c
		} else {
			pOut.Coeffs[i] *= c
		}
	}
}

// MonomialMulAssign multplies c*x^d to pOut.
// Panics if d < 0.
func (e Evaluater[T]) MonomialMulAssign(c T, d int, pOut Poly[T]) {
	if d < 0 {
		panic("d smaller than zero")
	}

	// We can only consider d % 2*N, since X^2N = 1.
	d %= 2 * e.degree

	// If N <= d < 2N, X^d = X^N * X^(d-N) = -X^(d-N).
	if d >= e.degree {
		e.MonomialMulAssign(-c, d-e.degree, pOut)
		return
	}

	vec.RotateAssign(pOut.Coeffs, d)

	for i := 0; i < e.degree; i++ {
		if i < d {
			pOut.Coeffs[i] *= -c
		} else {
			pOut.Coeffs[i] *= c
		}
	}
}
