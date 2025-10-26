package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// AddGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.AddGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// AddGLWETo computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddGLWETo(ctOut, ct0, ct1 GLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.AddPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// AddPlainGLWE returns ct0 + pt.
func (e *Evaluator[T]) AddPlainGLWE(ct GLWECiphertext[T], pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.AddPlainGLWETo(ctOut, ct, pt)
	return ctOut
}

// AddPlainGLWETo computes ctOut = ct + pt.
func (e *Evaluator[T]) AddPlainGLWETo(ctOut, ct GLWECiphertext[T], pt GLWEPlaintext[T]) {
	for i := 1; i < e.Params.glweRank+1; i++ {
		ctOut.Value[i].CopyFrom(ct.Value[i])
	}
	e.PolyEvaluator.AddPolyTo(ctOut.Value[0], ct.Value[0], pt.Value)
}

// SubGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.SubGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// SubGLWETo computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubGLWETo(ctOut, ct0, ct1 GLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.SubPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// SubPlainGLWE returns ct - pt.
func (e *Evaluator[T]) SubPlainGLWE(ct GLWECiphertext[T], pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.SubPlainGLWETo(ctOut, ct, pt)
	return ctOut
}

// SubPlainGLWETo computes ctOut = ct - pt.
func (e *Evaluator[T]) SubPlainGLWETo(ctOut, ct GLWECiphertext[T], pt GLWEPlaintext[T]) {
	for i := 1; i < e.Params.glweRank+1; i++ {
		ctOut.Value[i].CopyFrom(ct.Value[i])
	}
	e.PolyEvaluator.SubPolyTo(ctOut.Value[0], ct.Value[0], pt.Value)
}

// NegGLWE returns -ct.
func (e *Evaluator[T]) NegGLWE(ct GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.NegGLWETo(ctOut, ct)
	return ctOut
}

// NegGLWETo computes ctOut = -ct.
func (e *Evaluator[T]) NegGLWETo(ctOut, ct GLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.NegPolyTo(ctOut.Value[i], ct.Value[i])
	}
}

// ScalarMulGLWE returns c * ct.
func (e *Evaluator[T]) ScalarMulGLWE(ct GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.ScalarMulGLWETo(ctOut, ct, c)
	return ctOut
}

// ScalarMulGLWETo computes ctOut = c * ct.
func (e *Evaluator[T]) ScalarMulGLWETo(ctOut, ct GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// ScalarMulAddGLWETo computes ctOut += c * ct.
func (e *Evaluator[T]) ScalarMulAddGLWETo(ctOut, ct GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulAddPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// ScalarMulSubGLWETo computes ctOut -= c * ct.
func (e *Evaluator[T]) ScalarMulSubGLWETo(ctOut, ct GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.ScalarMulSubPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// PolyMulGLWE returns p * ct.
func (e *Evaluator[T]) PolyMulGLWE(ct GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.PolyMulGLWETo(ctOut, ct, p)
	return ctOut
}

// PolyMulGLWETo computes ctOut = p * ct.
func (e *Evaluator[T]) PolyMulGLWETo(ctOut, ct GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulPolyTo(ctOut.Value[i], ct.Value[i], p)
	}
}

// PolyMulAddGLWETo computes ctOut += p * ct.
func (e *Evaluator[T]) PolyMulAddGLWETo(ctOut, ct GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulAddPolyTo(ctOut.Value[i], ct.Value[i], p)
	}
}

// PolyMulSubGLWETo computes ctOut -= p * ct.
func (e *Evaluator[T]) PolyMulSubGLWETo(ctOut, ct GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulSubPolyTo(ctOut.Value[i], ct.Value[i], p)
	}
}

// FFTPolyMulGLWE returns fp * ct.
func (e *Evaluator[T]) FFTPolyMulGLWE(ct GLWECiphertext[T], fp poly.FFTPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.FFTPolyMulGLWETo(ctOut, ct, fp)
	return ctOut
}

// FFTPolyMulGLWETo computes ctOut = fp * ct.
func (e *Evaluator[T]) FFTPolyMulGLWETo(ctOut, ct GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FFTPolyMulPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulAddGLWETo computes ctOut += fp * ct.
func (e *Evaluator[T]) FFTPolyMulAddGLWETo(ctOut, ct GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FFTPolyMulAddPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulSubGLWETo computes ctOut -= fp * ct.
func (e *Evaluator[T]) FFTPolyMulSubGLWETo(ctOut, ct GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FFTPolyMulSubPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// MonomialMulGLWE returns X^d * ct.
func (e *Evaluator[T]) MonomialMulGLWE(ct GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.MonomialMulGLWETo(ctOut, ct, d)
	return ctOut
}

// MonomialMulGLWETo computes ctOut = X^d * ct.
//
// ct and ctOut should not overlap. For inplace multiplication,
// use [*Evaluator.MonomialMulGLWEInPlace].
func (e *Evaluator[T]) MonomialMulGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// MonomialMulGLWEInPlace computes ct = X^d * ct.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulPolyInPlace(ct.Value[i], d)
	}
}

// MonomialMulAddGLWETo computes ctOut += X^d * ct.
//
// ct and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulAddPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// MonomialMulSubGLWETo computes ctOut -= X^d * ct.
//
// ct and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MonomialMulSubPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteGLWE returns ctOut = ct(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWE(ct GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.PermuteGLWETo(ctOut, ct, d)
	return ctOut
}

// PermuteGLWETo computes ctOut = ct(X^d).
//
// ct and ctOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteGLWEInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermutePolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteGLWEInPlace computes ct = ct(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWEInPlace(ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermutePolyInPlace(ct.Value[i], d)
	}
}

// PermuteAddGLWETo computes ctOut += ct(X^d).
//
// ct and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteAddPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteSubGLWETo computes ctOut -= ct(X^d).
//
// ct and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteSubPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}
