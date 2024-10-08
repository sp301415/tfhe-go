package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// AddGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEAssign computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.AddPolyAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// AddPlainGLWE returns ct0 + pt.
func (e *Evaluator[T]) AddPlainGLWE(ct0 GLWECiphertext[T], pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddPlainGLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// AddPlainGLWEAssign computes ctOut = ct0 + pt.
func (e *Evaluator[T]) AddPlainGLWEAssign(ct0 GLWECiphertext[T], pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	for i := 1; i < e.Parameters.glweRank+1; i++ {
		ctOut.Value[i].CopyFrom(ct0.Value[i])
	}
	e.PolyEvaluator.AddPolyAssign(ct0.Value[0], pt.Value, ctOut.Value[0])
}

// SubGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEAssign computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubGLWEAssign(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.SubPolyAssign(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubPlainGLWE returns ct0 - pt.
func (e *Evaluator[T]) SubPlainGLWE(ct0 GLWECiphertext[T], pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubPlainGLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// SubPlainGLWEAssign computes ctOut = ct0 - pt.
func (e *Evaluator[T]) SubPlainGLWEAssign(ct0 GLWECiphertext[T], pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	for i := 1; i < e.Parameters.glweRank+1; i++ {
		ctOut.Value[i].CopyFrom(ct0.Value[i])
	}
	e.PolyEvaluator.SubPolyAssign(ct0.Value[0], pt.Value, ctOut.Value[0])
}

// NegGLWE returns -ct0.
func (e *Evaluator[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.NegGLWEAssign(ct0, ctOut)
	return ctOut
}

// NegGLWEAssign computes ctOut = -ct0.
func (e *Evaluator[T]) NegGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.NegPolyAssign(ct0.Value[i], ctOut.Value[i])
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
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulAddPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// ScalarMulSubGLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubGLWEAssign(ct0 GLWECiphertext[T], c T, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulSubPolyAssign(ct0.Value[i], c, ctOut.Value[i])
	}
}

// PolyMulGLWE returns p * ct0.
func (e *Evaluator[T]) PolyMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PolyMulGLWEAssign(ct0, p, ctOut)
	return ctOut
}

// PolyMulGLWEAssign computes ctOut = p * ct0.
func (e *Evaluator[T]) PolyMulGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MulPolyAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulAddGLWEAssign computes ctOut += p * ct0.
func (e *Evaluator[T]) PolyMulAddGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MulAddPolyAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// PolyMulSubGLWEAssign computes ctOut -= p * ct0.
func (e *Evaluator[T]) PolyMulSubGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MulSubPolyAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// FourierPolyMulGLWE returns fp * ct0.
func (e *Evaluator[T]) FourierPolyMulGLWE(ct0 GLWECiphertext[T], fp poly.FourierPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.FourierPolyMulGLWEAssign(ct0, fp, ctOut)
	return ctOut
}

// FourierPolyMulGLWEAssign computes ctOut = fp * ct0.
func (e *Evaluator[T]) FourierPolyMulGLWEAssign(ct0 GLWECiphertext[T], fp poly.FourierPoly, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.FourierPolyMulPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulAddGLWEAssign computes ctOut += fp * ct0.
func (e *Evaluator[T]) FourierPolyMulAddGLWEAssign(ct0 GLWECiphertext[T], fp poly.FourierPoly, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.FourierPolyMulAddPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
	}
}

// FourierPolyMulSubGLWEAssign computes ctOut -= fp * ct0.
func (e *Evaluator[T]) FourierPolyMulSubGLWEAssign(ct0 GLWECiphertext[T], fp poly.FourierPoly, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.FourierPolyMulSubPolyAssign(ct0.Value[i], fp, ctOut.Value[i])
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
// ct0 and ctOut should not overlap. For inplace multiplication,
// use [*Evaluator.MonomialMulGLWEInPlace].
func (e *Evaluator[T]) MonomialMulGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulPolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulGLWEInPlace computes ct0 = X^d * ct0.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulPolyInPlace(ct0.Value[i], d)
	}
}

// MonomialMulAddGLWEAssign computes ctOut += X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulAddPolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// MonomialMulSubGLWEAssign computes ctOut -= X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulSubPolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// PermuteGLWE returns ctOut = ct0(X^d).
func (e *Evaluator[T]) PermuteGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.PermuteGLWEAssign(ct0, d, ctOut)
	return ctOut
}

// PermuteGLWEAssign computes ctOut = ct0(X^d).
//
// ct0 and ctOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteGLWEInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.PermutePolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// PermuteGLWEInPlace computes ct0 = ct0(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.PermutePolyInPlace(ct0.Value[i], d)
	}
}

// PermuteAddGLWEAssign computes ctOut += ct0(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.PermuteAddPolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}

// PermuteSubGLWEAssign computes ctOut -= ct0(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubGLWEAssign(ct0 GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.PermuteSubPolyAssign(ct0.Value[i], d, ctOut.Value[i])
	}
}
