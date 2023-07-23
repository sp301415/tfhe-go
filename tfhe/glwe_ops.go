package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// AddGLWE adds two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEInPlace adds two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluator[T]) AddGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.AddInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubGLWE subtracts two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEInPlace subtracts two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluator[T]) SubGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.SubInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegGLWE negates ct0 and returns the result.
func (e Evaluator[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.NegGLWEInPlace(ct0, ctOut)
	return ctOut
}

// NegGLWEInPlace negates ct0 and writes it to ctOut.
func (e Evaluator[T]) NegGLWEInPlace(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.NegInPlace(ct0.Value[i], ctOut.Value[i])
	}
}

// ScalarMulGLWE multplies c to ct0 and returns the result.
func (e Evaluator[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ScalarMulGLWEInPlace(ct0, c, ctOut)
	return ctOut
}

// ScalarMulGLWEInPlace multplies c to ct0 and writes it to ctOut.
func (e Evaluator[T]) ScalarMulGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEInPlace multplies c to ct0 and adds to ctOut.
func (e Evaluator[T]) ScalarMulAddGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulAddInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEInPlace multplies c to ct0 and subtracts from Out.
func (e Evaluator[T]) ScalarMulSubGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.ScalarMulSubInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// PolyAddGLWE adds p to ct0 and returns the result.
func (e Evaluator[T]) PolyAddGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyAddGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyAddGLWEInPlace adds p to ct0 and writes to ctOut.
func (e Evaluator[T]) PolyAddGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	e.PolyEvaluator.AddInPlace(ct0.Value[0], p, ctOut.Value[0])

}

// PolyMulGLWE multiplies p to ct0 and returns the result.
func (e Evaluator[T]) PolyMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyMulGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyMulGLWEInPlace multiplies p to ct0 and writes to ctOut.
func (e Evaluator[T]) PolyMulGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulAddGLWEInPlace multiplies p to ct0 and adds to ctOut.
func (e Evaluator[T]) PolyMulAddGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAddInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEInPlace multiplies p to ct0 and subtracts from ctOut.
func (e Evaluator[T]) PolyMulSubGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulSubInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// MonomialMulGLWE multplies X^d to ct0 and returns the result.
// Assumes d >= 0.
func (e Evaluator[T]) MonomialMulGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialMulGLWEInPlace(ct0, d, ctOut)
	return ctOut
}

// MonomialMulGLWEInPlace multplies X^d to ct0 and writes it to ctOut.
// Assumes d >= 0.
func (e Evaluator[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialMulInPlace(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulGLWE divides X^d from ct0 and returns the result.
// Panics if d < 0.
func (e Evaluator[T]) MonomialDivGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialDivGLWEInPlace(ct0, d, ctOut)
	return ctOut
}

// MonomialDivGLWEInPlace divides X^d from ct0 and writes it to ctOut.
// Assumes d >= 0.
func (e Evaluator[T]) MonomialDivGLWEInPlace(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MonomialDivInPlace(ct0.Value[i], d, ctOut.Value[i])
	}
}
