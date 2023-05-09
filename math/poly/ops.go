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
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulInPlace(p0 Poly[T], c T, d int, pOut Poly[T]) {
	// We can only consider d % 2*N, since X^2N = 1.
	d %= 2 * e.degree

	// If N <= d < 2N, X^d = X^N * X^(d-N) = -X^(d-N).
	if d >= e.degree {
		e.MonomialMulInPlace(p0, -c, d-e.degree, pOut)
		return
	}

	for i := 0; i < e.degree; i++ {
		//                   d
		// |++++++++++++++|+++++| p0
		// |-----|++++++++++++++| pOut
		//    d
		if i < e.degree-d {
			pOut.Coeffs[i+d] = c * p0.Coeffs[i]
		} else {
			pOut.Coeffs[i-(e.degree-d)] = -c * p0.Coeffs[i]
		}
	}
}

// MonomialMulAssign multplies c*x^d to pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulAssign(c T, d int, pOut Poly[T]) {
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

// MonomialMulAddAssign multiplies c*X^d to p0 and adds it to pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulAddAssign(p0 Poly[T], c T, d int, pOut Poly[T]) {
	// We can only consider d % 2*N, since X^2N = 1.
	d %= 2 * e.degree

	// If N <= d < 2N, X^d = X^N * X^(d-N) = -X^(d-N).
	if d >= e.degree {
		e.MonomialMulInPlace(p0, -c, d-e.degree, pOut)
		return
	}

	for i := 0; i < e.degree; i++ {
		if i < e.degree-d {
			pOut.Coeffs[i+d] += c * p0.Coeffs[i]
		} else {
			pOut.Coeffs[i-(e.degree-d)] += -c * p0.Coeffs[i]
		}
	}
}

// MonomialMulSubAssign multiplies c*X^d to p0 and subtracts it from pOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulSubAssign(p0 Poly[T], c T, d int, pOut Poly[T]) {
	// We can only consider d % 2*N, since X^2N = 1.
	d %= 2 * e.degree

	// If N <= d < 2N, X^d = X^N * X^(d-N) = -X^(d-N).
	if d >= e.degree {
		e.MonomialMulInPlace(p0, -c, d-e.degree, pOut)
		return
	}

	for i := 0; i < e.degree; i++ {
		if i < e.degree-d {
			pOut.Coeffs[i+d] -= c * p0.Coeffs[i]
		} else {
			pOut.Coeffs[i-(e.degree-d)] -= -c * p0.Coeffs[i]
		}
	}
}
