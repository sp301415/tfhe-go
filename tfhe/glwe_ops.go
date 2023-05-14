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

// AddGLWEAssign adds GLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.AddAssign(ct0.Value[i], ctOut.Value[i])
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

// SubGLWEAssign subtracts GLWE ciphertext ct0 from ctOut.
func (e Evaluater[T]) SubGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.SubAssign(ct0.Value[i], ctOut.Value[i])
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

// NegGLWEAssign negates ct0.
func (e Evaluater[T]) NegGLWEAssign(ct0 GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.NegAssign(ct0.Value[i])
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

// ScalarMulGLWEAssign multplies c to ctOut.
func (e Evaluater[T]) ScalarMulGLWEAssign(c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.ScalarMulAssign(c, ctOut.Value[i])
	}
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

// PolyMulGLWEAssign multiplies p to ctOut.
func (e Evaluater[T]) PolyMulGLWEAssign(p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulAssign(p, ctOut.Value[i])
	}
}

// PolyMulAddGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) PolyMulAddGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulAddAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) PolyMujlSubGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulSubAssign(ct0.Value[i], p, ctOut.Value[i])
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

// MonomialMulGLWEAssign multplies X^d to ctOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialMulGLWEAssign(d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MonomialMulAssign(d, ctOut.Value[i])
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

// MonomialMulAssignGLWE divides X^d from ctOut.
// Assumes d >= 0.
func (e Evaluater[T]) MonomialDivGLWEAssign(d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MonomialDivAssign(d, ctOut.Value[i])
	}
}
