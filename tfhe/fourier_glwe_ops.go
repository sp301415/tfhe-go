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

// PolyMulFourierGLWE multiplies p to ct0 and returns the result.
func (e Evaluater[T]) PolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], p poly.Poly[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.PolyMulFourierGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// PolyMulFourierGLWEInPlace multiplies p to ct0 and writes to ctOut.
func (e Evaluater[T]) PolyMulFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyInPlace(p, e.buffer.fpForOps)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulInPlace(ct0.Value[i], e.buffer.fpForOps, ctOut.Value[i])
	}
}

// PolyMulAddFourierGLWEInPlace multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) PolyMulAddFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyInPlace(p, e.buffer.fpForOps)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAddInPlace(ct0.Value[i], e.buffer.fpForOps, ctOut.Value[i])
	}
}

// PolyMulSubFourierGLWEInPlace multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) PolyMulSubFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyInPlace(p, e.buffer.fpForOps)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulSubInPlace(ct0.Value[i], e.buffer.fpForOps, ctOut.Value[i])
	}
}

// FourierPolyAddGLWE adds p to ct0 and returns the result.
func (e Evaluater[T]) FourierPolyAddFourierGLWE(ct0 FourierGLWECiphertext[T], p poly.FourierPoly) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.FourierPolyAddFourierGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// FourierPolyAddGLWEInPlace adds p to ct0 and writes to ctOut.
func (e Evaluater[T]) FourierPolyAddFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], p poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.AddInPlace(ct0.Value[0], p, ctOut.Value[0])
}

// FourierPolyMulFourierGLWE multiplies fp to ct0 and returns the result.
func (e Evaluater[T]) FourierPolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.FourierPolyMulFourierGLWEInPlace(ct0, fp, ctOut)
	return ctOut
}

// FourierPolyMulFourierGLWEInPlace multiplies fp to ct0 and writes to ctOut.
func (e Evaluater[T]) FourierPolyMulFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulInPlace(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulAddFourierGLWEInPlace multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) FourierPolyMulAddFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAddInPlace(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulSubFourierGLWEInPlace multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) FourierPolyMulSubFourierGLWEInPlace(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulSubInPlace(ct0.Value[i], fp, ctOut.Value[i])
	}
}
