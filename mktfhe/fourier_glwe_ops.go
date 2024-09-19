package mktfhe

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
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.AddFourierPolyAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
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
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.SubFourierPolyAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
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
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.NegFourierPolyAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// FloatMulFourierGLWE returns c * ct0.
func (e *Evaluator[T]) FloatMulFourierGLWE(ct0 FourierGLWECiphertext[T], c float64) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.FloatMulFourierGLWEAssign(ct0, c, ctOut)
	return ctOut
}

// FloatMulFourierGLWEAssign computes ctOut = c * ct0.
func (e *Evaluator[T]) FloatMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c float64, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.FloatMulFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// FloatMulAddFourierGLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) FloatMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c float64, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.FloatMulAddFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// FloatMulSubFourierGLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) FloatMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c float64, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.FloatMulSubFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// CmplxMulFourierGLWE returns c * ct0.
func (e *Evaluator[T]) CmplxMulFourierGLWE(ct0 FourierGLWECiphertext[T], c complex128) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.CmplxMulFourierGLWEAssign(ct0, c, ctOut)
	return ctOut
}

// CmplxMulFourierGLWEAssign computes ctOut = c * ct0.
func (e *Evaluator[T]) CmplxMulFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c complex128, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.CmplxMulFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// CmplxMulAddFourierGLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) CmplxMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c complex128, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.CmplxMulAddFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// CmplxMulSubFourierGLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) CmplxMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], c complex128, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.CmplxMulSubFourierPolyAssign(ct0.Value[i], c, ctOut.Value[i])
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
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.PolyMulFourierPolyAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulAddFourierGLWEAssign computes ctOut += p * ct0.
func (e *Evaluator[T]) PolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.PolyMulAddFourierPolyAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulSubFourierGLWEAssign computes ctOut -= p * ct0.
func (e *Evaluator[T]) PolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], p poly.Poly[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.PolyMulSubFourierPolyAssign(ct0.Value[i], p, ctOut.Value[i])
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
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.MulFourierPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulAddFourierGLWEAssign computes ctOut += fp * ct0.
func (e *Evaluator[T]) FourierPolyMulAddFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.MulAddFourierPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulSubFourierGLWEAssign computes ctOut -= fp * ct0.
func (e *Evaluator[T]) FourierPolyMulSubFourierGLWEAssign(ct0 FourierGLWECiphertext[T], fp poly.FourierPoly, ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.MulSubFourierPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}
