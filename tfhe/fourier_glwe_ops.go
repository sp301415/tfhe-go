package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// AddFourierGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.AddFourierGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddFourierGLWEAssign computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddFourierGLWEAssign(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.AddAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubFourierGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubFourierGLWE(ct0, ct1 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.SubFourierGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubFourierGLWEAssign computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubFourierGLWEAssign(ct0, ct1, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.SubAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// NegFourierGLWE returns -ct0.
func (e *Evaluator[T]) NegFourierGLWE(ct0 FourierGLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.NegFourierGLWEAssign(ct0, ctOut)
	return ctOut
}

// NegFourierGLWEAssign computes ctOut = -ct0.
func (e *Evaluator[T]) NegFourierGLWEAssign(ct0, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.NegAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// PolyMulFourierGLWE returns p * ct0.
func (e *Evaluator[T]) PolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], p poly.Poly[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.PolyMulFourierGLWEAssign(ct0, p, ctOut)
	return ctOut
}

// PolyMulFourierGLWEAssign computes ctOut = p * ct0.
func (e *Evaluator[T]) PolyMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierEvaluator.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// PolyMulAddFourierGLWEAssign computes ctOut += p * ct0.
func (e *Evaluator[T]) PolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierEvaluator.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulAddAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// PolyMulSubFourierGLWEAssign computes ctOut -= p * ct0.
func (e *Evaluator[T]) PolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	e.FourierEvaluator.ToFourierPolyAssign(p, e.buffer.fpOut)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulSubAssign(ct0.Value[i], e.buffer.fpOut, ctOut.Value[i])
	}
}

// FourierPolyMulFourierGLWE returns fp * ct0.
func (e *Evaluator[T]) FourierPolyMulFourierGLWE(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.FourierPolyMulFourierGLWEAssign(ct0, fp, ctOut)
	return ctOut
}

// FourierPolyMulFourierGLWEAssign computes ctOut = fp * ct0.
func (e *Evaluator[T]) FourierPolyMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulAddFourierGLWEAssign computes ctOut += fp * ct0.
func (e *Evaluator[T]) FourierPolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulAddAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulSubFourierGLWEAssign computes ctOut -= fp * ct0.
func (e *Evaluator[T]) FourierPolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.MulSubAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}
