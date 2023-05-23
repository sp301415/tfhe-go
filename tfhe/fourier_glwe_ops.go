package tfhe

import "github.com/sp301415/tfhe/math/poly"

// AddFourierGLWE adds two FourierGLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.AddFourierGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddFourierGLWEInPlace adds two FourierGLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddFourierGLWEInPlace(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.AddInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// AddFourierGLWEAssign adds FourierGLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddFourierGLWEAssign(ct0, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.AddAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// SubFourierGLWE subtracts two FourierGLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) SubFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.SubFourierGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubFourierGLWEInPlace subtracts two FourierGLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) SubFourierGLWEInPlace(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.SubInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubFourierGLWEAssign subtracts FourierGLWE ciphertext ct0 from ctOut.
func (e Evaluater[T]) SubFourierGLWEAssign(ct0, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.SubAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// NegFourierGLWE negates ct0 and returns the result.
func (e Evaluater[T]) NegFourierGLWE(ct0 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.NegFourierGLWEInPlace(ct0, ctOut)
	return ctOut
}

// NegFourierGLWEInPlace negates ct0 and writes it to ctOut.
func (e Evaluater[T]) NegFourierGLWEInPlace(ct0, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.NegInPlace(ct0.Value[i], ctOut.Value[i])
	}
}

// NegFourierGLWEAssign negates ct0.
func (e Evaluater[T]) NegFourierGLWEAssign(ct0 FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.NegAssign(ct0.Value[i])
	}
}

// PolyMulFourierGLWE multiplies p to ct0 and returns the result.
func (e Evaluater[T]) PolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], p poly.Poly[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.PolyMulFourierGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyMulFourierGLWEInPlace multiplies p to ct0 and writes to ctOut.
func (e Evaluater[T]) PolyMulFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.PolyMulInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulFourierGLWEAssign multiplies p to ctOut.
func (e Evaluater[T]) PolyMulFourierGLWEAssign(p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.PolyMulAssign(p, ctOut.Value[i])
	}
}

// PolyMulAddFourierGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) PolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.PolyMulAddAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulAddFourierGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) PolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.PolyMulSubAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}
