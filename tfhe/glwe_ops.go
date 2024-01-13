package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// PlaintextAddGLWE returns pt + ct0.
func (e *Evaluator[T]) PlaintextAddGLWE(pt GLWEPlaintext[T], ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PlaintextAddGLWEAssign(pt, ct0, ctOut)
	return ctOut
}

// PlaintextAddGLWEAssign computes ctOut = pt + ct0.
func (e *Evaluator[T]) PlaintextAddGLWEAssign(pt GLWEPlaintext[T], ct0, ctOut GLWECiphertext[T]) {
	e.PolyEvaluator.AddAssign(pt.Value, ct0.Value[0], ctOut.Value[0])

}

// AddGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEAssign computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.AddAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEAssign computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.SubAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegGLWE returns -ct0.
func (e *Evaluator[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.NegGLWEAssign(ct0, ctOut)
	return ctOut
}

// NegGLWEAssign computes ctOut = -ct0.
func (e *Evaluator[T]) NegGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.NegAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// ScalarMulGLWE returns c * ct0.
func (e *Evaluator[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ScalarMulGLWEAssign(ct0, c, ctOut)
	return ctOut
}

// ScalarMulGLWEAssign computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulAddAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulSubAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// PolyMulGLWE returns p * ct0.
func (e *Evaluator[T]) PolyMulGLWE(p poly.Poly[T], ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyMulGLWEAssign(p, ct0, ctOut)
	return ctOut
}

// PolyMulGLWEAssign computes ctOut = p * ct0.
func (e *Evaluator[T]) PolyMulGLWEAssign(p poly.Poly[T], ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAssign(p, ct0.Value[i], ctOut.Value[i])
	}
}

// PolyMulAddGLWEAssign computes ctOut += p * ct0.
func (e *Evaluator[T]) PolyMulAddGLWEAssign(p poly.Poly[T], ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAddAssign(p, ct0.Value[i], ctOut.Value[i])
	}
}

// PolyMulSubGLWEAssign computes ctOut -= p * ct0.
func (e *Evaluator[T]) PolyMulSubGLWEAssign(p poly.Poly[T], ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulSubAssign(p, ct0.Value[i], ctOut.Value[i])
	}
}

// MonomialMulGLWE returns X^d * ct0.
func (e *Evaluator[T]) MonomialMulGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialMulGLWEAssign(ct0, d, ctOut)
	return ctOut
}

// MonomialMulGLWEAssign computes ctOut = X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulGLWEInPlace computes ct0 = X^d * ct0.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulInPlace(ct0.Value[i], d)
	}
}

// MonomialMulAddGLWEAssign computes ctOut += X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulAddAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulSubGLWEAssign computes ctOut -= X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulSubAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulSubOneMulAssign computes ctOut = (X^d - 1) * ct0.
//
// d should be positive, and ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialSubOneMulGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialSubOneMulAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulSubOneMulAddAssign computes ctOut += (X^d - 1) * ct0.
//
// d should be positive, and ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialSubOneMulAddGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialSubOneMulAddAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}
