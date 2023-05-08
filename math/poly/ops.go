package poly

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
	"golang.org/x/exp/constraints"
)

// Add adds p0, p1 and returns the result.
func (e Evaluater[T]) Add(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	vec.AddInPlace(p0.Coeffs, p1.Coeffs, p.Coeffs)
	return p
}

// AddInPlace adds p0, p1 and writes it to pOut.
func (e Evaluater[T]) AddInPlace(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = p0.Coeffs[i] + p1.Coeffs[i]
	}
}

// AddAssign adds p0 to ptOut.
func (e Evaluater[T]) AddAssign(p0, pOut Poly[T]) {
	e.AddInPlace(p0, pOut, pOut)
}

// Sub subtracts p0, p1 and returns the result.
func (e Evaluater[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.SubInPlace(p0, p1, p)
	return p
}

// SubInPlace subtracts p0, p1 and writes it to pOut.
func (e Evaluater[T]) SubInPlace(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = p0.Coeffs[i] - p1.Coeffs[i]
	}
}

// SubAssign subtracts p0 from pOut.
func (e Evaluater[T]) SubAssign(p0, pOut Poly[T]) {
	e.SubInPlace(pOut, p0, pOut)
}

// Neg negates p0 and returns the result.
func (e Evaluater[T]) Neg(p0 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.NegInPlace(p0, p)
	return p
}

// NegInPlace negates p0 and writes it to pOut.
func (e Evaluater[T]) NegInPlace(p0, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = -p0.Coeffs[i]
	}
}

// NegAssign negates p0.
func (e Evaluater[T]) NegAssign(p0 Poly[T]) {
	e.NegInPlace(p0, p0)
}

// Mul multiplies p0, p1 and returns the result.
func (e Evaluater[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.MulInPlace(p0, p1, p)
	return p
}

// fromFloat converts float64 to T, wrapping with MaxT.
func fromFloat[T constraints.Integer](f float64) T {
	maxT := float64(num.MaxT[T]())
	for f < 0 {
		f += maxT
	}
	for f > maxT {
		f -= maxT
	}
	return T(f)
}

// MulInPlace multiplies p0, p1 and writes it to pOut.
func (e Evaluater[T]) MulInPlace(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = fromFloat[T](e.buffpOutf[i])
	}
}

// MulAssign multiplies p0 to pOut.
func (e Evaluater[T]) MulAssign(p0, pOut Poly[T]) {
	e.MulInPlace(p0, pOut, pOut)
}

// MulAddAssign multiplies p0, p1 and adds to pOut.
func (e Evaluater[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] += fromFloat[T](e.buffpOutf[i])
	}
}

// MulSubAssign multiplies p0, p1 and subtracts from pOut.
func (e Evaluater[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] -= fromFloat[T](e.buffpOutf[i])
	}
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
