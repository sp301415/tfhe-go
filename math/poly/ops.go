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
func (e Evaluater[T]) MulWithFourier(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(e.degree)
	e.MulWithFourierInPlace(fp0, fp1, fp)
	return fp
}

// MulFourierInPlace multiplies fp0, fp1 and writes it to fpOut.
func (e Evaluater[T]) MulWithFourierInPlace(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulInPlace(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
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
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = c * p0.Coeffs[i]
	}
}

// ScalarMulAssign multplies c to pOut.
func (e Evaluater[T]) ScalarMulAssign(c T, pOut Poly[T]) {
	e.ScalarMulInPlace(pOut, c, pOut)
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
