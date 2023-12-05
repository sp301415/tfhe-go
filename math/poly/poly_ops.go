package poly

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// Add adds p0, p1 and returns the result.
func (e *Evaluator[T]) Add(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.AddAssign(p0, p1, p)
	return p
}

// AddAssign adds p0, p1 and writes it to pOut.
func (e *Evaluator[T]) AddAssign(p0, p1, pOut Poly[T]) {
	vec.AddAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Sub subtracts p0, p1 and returns the result.
func (e *Evaluator[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.SubAssign(p0, p1, p)
	return p
}

// SubAssign subtracts p0, p1 and writes it to pOut.
func (e *Evaluator[T]) SubAssign(p0, p1, pOut Poly[T]) {
	vec.SubAssign(p0.Coeffs, p1.Coeffs, pOut.Coeffs)
}

// Neg negates p0 and returns the result.
func (e *Evaluator[T]) Neg(p0 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.NegAssign(p0, p)
	return p
}

// NegAssign negates p0 and writes it to pOut.
func (e *Evaluator[T]) NegAssign(p0, pOut Poly[T]) {
	vec.NegAssign(p0.Coeffs, pOut.Coeffs)
}

// Mul multiplies p0, p1 and returns the result.
func (e *Evaluator[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.MulAssign(p0, p1, p)
	return p
}

// MulAssign multiplies p0, p1 and writes it to pOut.
func (e *Evaluator[T]) MulAssign(p0, p1, pOut Poly[T]) {
	if e.degree <= karatsubaRecurseThreshold {
		e.mulAssignNaive(p0, p1, pOut)
	} else {
		e.mulAssignKaratsuba(p0, p1, pOut)
	}
}

// MulAddAssign multiplies p0, p1 and adds it to pOut.
func (e *Evaluator[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.AddAssign(pOut, e.buffer.pOut, pOut)
}

// MulSubAssign multiplies p0, p1 and subtracts it from pOut.
func (e *Evaluator[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.MulAssign(p0, p1, e.buffer.pOut)
	e.SubAssign(pOut, e.buffer.pOut, pOut)
}

// ScalarMul multiplies c to p0 and returns the result.
func (e *Evaluator[T]) ScalarMul(p0 Poly[T], c T) Poly[T] {
	p := New[T](e.degree)
	e.ScalarMulAssign(p0, c, p)
	return p
}

// ScalarMulAssign multiplies c to p0 and writes it to pOut.
func (e *Evaluator[T]) ScalarMulAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulAddAssign multiplies c to p0 and adds it to pOut.
func (e *Evaluator[T]) ScalarMulAddAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulAddAssign(p0.Coeffs, c, pOut.Coeffs)
}

// ScalarMulSubAssign multiplies c to p0 and subtracts it from pOut.
func (e *Evaluator[T]) ScalarMulSubAssign(p0 Poly[T], c T, pOut Poly[T]) {
	vec.ScalarMulSubAssign(p0.Coeffs, c, pOut.Coeffs)
}

// MonomialMul multiplies X^d to p0 and returns the result.
func (e *Evaluator[T]) MonomialMul(p0 Poly[T], d int) Poly[T] {
	p := New[T](e.degree)
	e.MonomialMulAssign(p0, d, p)
	return p
}

// MonomialMulAssign multiplies X^d to p0 and writes it to pOut.
func (e *Evaluator[T]) MonomialMulAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		kk := k - e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] = p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] = -p0.Coeffs[i-kk]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < k; i++ {
			pOut.Coeffs[i] = -p0.Coeffs[i-k+e.degree]
		}
		for i := k; i < e.degree; i++ {
			pOut.Coeffs[i] = p0.Coeffs[i-k]
		}
	case -e.degree <= k && k < 0:
		kk := k + e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] = p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] = -p0.Coeffs[i-kk]
		}
	case k < -e.degree:
		kk := k + 2*e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] = -p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] = p0.Coeffs[i-kk]
		}
	}
}

// MonomialMulInPlace multiplies X^d to p0.
func (e *Evaluator[T]) MonomialMulInPlace(p0 Poly[T], d int) {
	kk := d % e.degree
	vec.RotateInPlace(p0.Coeffs, kk)

	switch k := d % (2 * e.degree); {
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

// MonomialMulAddAssign multiplies X^d to p0 and adds it to pOut.
func (e *Evaluator[T]) MonomialMulAddAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		kk := k - e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < k; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-k+e.degree]
		}
		for i := k; i < e.degree; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-k]
		}
	case -e.degree <= k && k < 0:
		kk := k + e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk]
		}
	case k < -e.degree:
		kk := k + 2*e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk]
		}
	}
}

// MonomialMulSubAssign multiplies X^d to p0 and subtracts it from pOut.
func (e *Evaluator[T]) MonomialMulSubAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		kk := k - e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] -= p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] -= -p0.Coeffs[i-kk]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < k; i++ {
			pOut.Coeffs[i] -= -p0.Coeffs[i-k+e.degree]
		}
		for i := k; i < e.degree; i++ {
			pOut.Coeffs[i] -= p0.Coeffs[i-k]
		}
	case -e.degree <= k && k < 0:
		kk := k + e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] -= p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] -= -p0.Coeffs[i-kk]
		}
	case k < -e.degree:
		kk := k + 2*e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] -= -p0.Coeffs[i-kk+e.degree]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] -= p0.Coeffs[i-kk]
		}
	}
}

// MonomialMulMinusOneAddAssign multiplies X^d-1 to p0, and adds it to pOut.
// This operation is frequently used in Blind Rotation,
// so we implement it as a special function.
func (e *Evaluator[T]) MonomialMulMinusOneAddAssign(p0 Poly[T], d int, pOut Poly[T]) {
	switch k := d % (2 * e.degree); {
	case e.degree <= k:
		kk := k - e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk+e.degree] - p0.Coeffs[i]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk] - p0.Coeffs[i]
		}
	case 0 <= k && k < e.degree:
		for i := 0; i < k; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-k+e.degree] - p0.Coeffs[i]
		}
		for i := k; i < e.degree; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-k] - p0.Coeffs[i]
		}
	case -e.degree <= k && k < 0:
		kk := k + e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk+e.degree] - p0.Coeffs[i]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk] - p0.Coeffs[i]
		}
	case k < -e.degree:
		kk := k + 2*e.degree
		for i := 0; i < kk; i++ {
			pOut.Coeffs[i] += -p0.Coeffs[i-kk+e.degree] - p0.Coeffs[i]
		}
		for i := kk; i < e.degree; i++ {
			pOut.Coeffs[i] += p0.Coeffs[i-kk] - p0.Coeffs[i]
		}
	}
}
