package tfhe

import "github.com/sp301415/tfhe/math/poly"

// AddFourierGLWE adds two FourierGLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluator[T]) AddFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.AddFourierGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddFourierGLWEAssign adds two FourierGLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluator[T]) AddFourierGLWEAssign(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.AddAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubFourierGLWE subtracts two FourierGLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluator[T]) SubFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.SubFourierGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubFourierGLWEAssign subtracts two FourierGLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluator[T]) SubFourierGLWEAssign(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.SubAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegFourierGLWE negates ct0 and returns the result.
func (e Evaluator[T]) NegFourierGLWE(ct0 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.NegFourierGLWEAssign(ct0, ctOut)
	return ctOut
}

// NegFourierGLWEAssign negates ct0 and writes it to ctOut.
func (e Evaluator[T]) NegFourierGLWEAssign(ct0, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.NegAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// PolyMulFourierGLWE multiplies p to ct0 and returns the result.
func (e Evaluator[T]) PolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], p poly.Poly[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.PolyMulFourierGLWEAssign(ct0, p, ctOut)
	return ctOut
}

// PolyMulFourierGLWEAssign multiplies p to ct0 and writes to ctOut.
func (e Evaluator[T]) PolyMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// PolyMulAddFourierGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e Evaluator[T]) PolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAddAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// PolyMulSubFourierGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e Evaluator[T]) PolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierTransformer.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulSubAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// FourierPolyMulFourierGLWE multiplies fp to ct0 and returns the result.
func (e Evaluator[T]) FourierPolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.FourierPolyMulFourierGLWEAssign(ct0, fp, ctOut)
	return ctOut
}

// FourierPolyMulFourierGLWEAssign multiplies fp to ct0 and writes to ctOut.
func (e Evaluator[T]) FourierPolyMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulAddFourierGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e Evaluator[T]) FourierPolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulAddAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulSubFourierGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e Evaluator[T]) FourierPolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.MulSubAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}
