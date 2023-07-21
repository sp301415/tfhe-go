package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// AddGLWE adds two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEInPlace adds two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.AddInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubGLWE subtracts two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEInPlace subtracts two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) SubGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.SubInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegGLWE negates ct0 and returns the result.
func (e Evaluater[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.NegGLWEInPlace(ct0, ctOut)
	return ctOut
}

// NegGLWEInPlace negates ct0 and writes it to ctOut.
func (e Evaluater[T]) NegGLWEInPlace(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.NegInPlace(ct0.Value[i], ctOut.Value[i])
	}
}

// ScalarMulGLWE multplies c to ct0 and returns the result.
func (e Evaluater[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ScalarMulGLWEInPlace(ct0, c, ctOut)
	return ctOut
}

// ScalarMulGLWEInPlace multplies c to ct0 and writes it to ctOut.
func (e Evaluater[T]) ScalarMulGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.ScalarMulInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEInPlace multplies c to ct0 and adds to ctOut.
func (e Evaluater[T]) ScalarMulAddGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.ScalarMulAddInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEInPlace multplies c to ct0 and subtracts from Out.
func (e Evaluater[T]) ScalarMulSubGLWEInPlace(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.ScalarMulSubInPlace(ct0.Value[i], c, ctOut.Value[i])
	}
}

// PolyAddGLWE adds p to ct0 and returns the result.
func (e Evaluater[T]) PolyAddGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyAddGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyAddGLWEInPlace adds p to ct0 and writes to ctOut.
func (e Evaluater[T]) PolyAddGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	e.PolyEvaluater.AddInPlace(ct0.Value[0], p, ctOut.Value[0])

}

// PolyMulGLWE multiplies p to ct0 and returns the result.
func (e Evaluater[T]) PolyMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyMulGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyMulGLWEInPlace multiplies p to ct0 and writes to ctOut.
func (e Evaluater[T]) PolyMulGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulAddGLWEInPlace multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) PolyMulAddGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulAddInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEInPlace multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) PolyMulSubGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulSubInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// MonomialMulGLWE multplies X^d to ct0 and returns the result.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialMulGLWEInPlace(ct0, d, ctOut)
	return ctOut
}

// MonomialMulGLWEInPlace multplies X^d to ct0 and writes it to ctOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MonomialMulInPlace(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulGLWE divides X^d from ct0 and returns the result.
// Panics if d < 0.
func (e Evaluater[T]) MonomialDivGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.MonomialDivGLWEInPlace(ct0, d, ctOut)
	return ctOut
}

// MonomialDivGLWEInPlace divides X^d from ct0 and writes it to ctOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialDivGLWEInPlace(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MonomialDivInPlace(ct0.Value[i], d, ctOut.Value[i])
	}
}
