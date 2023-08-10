package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// AddGLWE adds two GLWE cipheretexts ct0, ct1 and returns the result.
func (e *Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEAssign adds two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e *Evaluator[T]) AddGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.AddAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubGLWE subtracts two GLWE cipheretexts ct0, ct1 and returns the result.
func (e *Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEAssign subtracts two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e *Evaluator[T]) SubGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.SubAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegGLWE negates ct0 and returns the result.
func (e *Evaluator[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.NegGLWEAssign(ct0, ctOut)
	return ctOut
}

// NegGLWEAssign negates ct0 and writes it to ctOut.
func (e *Evaluator[T]) NegGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.NegAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// ScalarMulGLWE multplies c to ct0 and returns the result.
func (e *Evaluator[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ScalarMulGLWEAssign(ct0, c, ctOut)
	return ctOut
}

// ScalarMulGLWEAssign multplies c to ct0 and writes it to ctOut.
func (e *Evaluator[T]) ScalarMulGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign multplies c to ct0 and adds to ctOut.
func (e *Evaluator[T]) ScalarMulAddGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulAddAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEAssign multplies c to ct0 and subtracts from Out.
func (e *Evaluator[T]) ScalarMulSubGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulSubAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// PlaintextAddGLWE adds pt to ct0 and returns the result.
func (e *Evaluator[T]) PlaintextAddGLWE(ct0 GLWECiphertext[T], pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PlaintextAddGLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// PlaintextAddGLWEAssign adds p to ct0 and writes to ctOut.
func (e *Evaluator[T]) PlaintextAddGLWEAssign(ct0 GLWECiphertext[T], pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	e.PolyEvaluator.AddAssign(ct0.Value[0], pt.Value, ctOut.Value[0])

}

// PolyMulGLWE multiplies p to ct0 and returns the result.
func (e *Evaluator[T]) PolyMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyMulGLWEAssign(ct0, p, ctOut)
	return ctOut
}

// PolyMulGLWEAssign multiplies p to ct0 and writes to ctOut.
func (e *Evaluator[T]) PolyMulGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulAddGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e *Evaluator[T]) PolyMulAddGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAddAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulSubGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e *Evaluator[T]) PolyMulSubGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulSubAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// MonomialMulGLWE multplies X^d to ct0 and returns the result.
func (e *Evaluator[T]) MonomialMulGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialMulGLWEAssign(ct0, d, ctOut)
	return ctOut
}

// MonomialMulGLWEAssign multplies X^d to ct0 and writes it to ctOut.
func (e *Evaluator[T]) MonomialMulGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulGLWEInPlace multplies X^d to ct0.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulInPlace(ct0.Value[i], d)
	}
}

// MonomialMulMinusOneGLWEAssign multplies X^d-1 to ct0, and adds it to ctOut.
// This operation is frequently used in Blind Rotation,
// so we implement it as a special function.
func (e *Evaluator[T]) MonomialMulMinusOneAddGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulMinusOneAddAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}
