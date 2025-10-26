package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// AddGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.AddGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// AddGLWETo computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddGLWETo(ctOut, ct0, ct1 GLWECiphertext[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.AddPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// AddPlainGLWE returns ct0 + pt.
func (e *Evaluator[T]) AddPlainGLWE(ct0 GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.AddPlainGLWETo(ctOut, ct0, pt)
	return ctOut
}

// AddPlainGLWETo computes ctOut = ct0 + pt.
func (e *Evaluator[T]) AddPlainGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	for i := 1; i < e.Params.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(ct0.Value[i])
	}
	e.subEvaluator.PolyEvaluator.AddPolyTo(ctOut.Value[0], ct0.Value[0], pt.Value)
}

// SubGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.SubGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// SubGLWETo computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubGLWETo(ctOut, ct0, ct1 GLWECiphertext[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.SubPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// SubPlainGLWE returns ct0 - pt.
func (e *Evaluator[T]) SubPlainGLWE(ct0 GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.SubPlainGLWETo(ctOut, ct0, pt)
	return ctOut
}

// SubPlainGLWETo computes ctOut = ct0 - pt.
func (e *Evaluator[T]) SubPlainGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	for i := 1; i < e.Params.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(ct0.Value[i])
	}
	e.subEvaluator.PolyEvaluator.SubPolyTo(ctOut.Value[0], ct0.Value[0], pt.Value)
}

// NegGLWE returns -ct0.
func (e *Evaluator[T]) NegGLWE(ct0 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.NegGLWETo(ctOut, ct0)
	return ctOut
}

// NegGLWETo computes ctOut = -ct0.
func (e *Evaluator[T]) NegGLWETo(ctOut, ct0 GLWECiphertext[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.NegPolyTo(ctOut.Value[i], ct0.Value[i])
	}
}

// ScalarMulGLWE returns c * ct0.
func (e *Evaluator[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], c T) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.ScalarMulGLWETo(ctOut, ct0, c)
	return ctOut
}

// ScalarMulGLWETo computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[i], ct0.Value[i], c)
	}
}

// ScalarMulAddGLWETo computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulAddPolyTo(ctOut.Value[i], ct0.Value[i], c)
	}
}

// ScalarMulSubGLWETo computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulSubPolyTo(ctOut.Value[i], ct0.Value[i], c)
	}
}

// PolyMulGLWE returns p * ct0.
func (e *Evaluator[T]) PolyMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.PolyMulGLWETo(ctOut, ct0, p)
	return ctOut
}

// PolyMulGLWETo computes ctOut = p * ct0.
func (e *Evaluator[T]) PolyMulGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulPolyTo(ctOut.Value[i], ct0.Value[i], p)
	}
}

// PolyMulAddGLWETo computes ctOut += p * ct0.
func (e *Evaluator[T]) PolyMulAddGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulAddPolyTo(ctOut.Value[i], ct0.Value[i], p)
	}
}

// PolyMulSubGLWETo computes ctOut -= p * ct0.
func (e *Evaluator[T]) PolyMulSubGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulSubPolyTo(ctOut.Value[i], ct0.Value[i], p)
	}
}

// FFTPolyMulGLWE returns fp * ct0.
func (e *Evaluator[T]) FFTPolyMulGLWE(ct0 GLWECiphertext[T], fp poly.FFTPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.FFTPolyMulGLWETo(ctOut, ct0, fp)
	return ctOut
}

// FFTPolyMulGLWETo computes ctOut = fp * ct0.
func (e *Evaluator[T]) FFTPolyMulGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.FFTPolyMulPolyTo(ctOut.Value[i], ct0.Value[i], fp)
	}
}

// FFTPolyMulAddGLWETo computes ctOut += fp * ct0.
func (e *Evaluator[T]) FFTPolyMulAddGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.FFTPolyMulAddPolyTo(ctOut.Value[i], ct0.Value[i], fp)
	}
}

// FFTPolyMulSubGLWETo computes ctOut -= fp * ct0.
func (e *Evaluator[T]) FFTPolyMulSubGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.FFTPolyMulSubPolyTo(ctOut.Value[i], ct0.Value[i], fp)
	}
}

// MonomialMulGLWE returns X^d * ct0.
func (e *Evaluator[T]) MonomialMulGLWE(ct0 GLWECiphertext[T], d int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.MonomialMulGLWETo(ctOut, ct0, d)
	return ctOut
}

// MonomialMulGLWETo computes ctOut = X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}

// MonomialMulGLWEInPlace computes ct0 = X^d * ct0.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulPolyInPlace(ct0.Value[i], d)
	}
}

// MonomialMulAddGLWETo computes ctOut += X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulAddPolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}

// MonomialMulSubGLWETo computes ctOut -= X^d * ct0.
//
// ct0 and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulSubPolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}

// PermuteGLWETo computes ctOut = ct0(X^d).
//
// ct0 and ctOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteGLWEInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermutePolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}

// PermuteGLWEInPlace computes ct0 = ct0(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWEInPlace(ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermutePolyInPlace(ct0.Value[i], d)
	}
}

// PermuteAddGLWETo computes ctOut += ct0(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermuteAddPolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}

// PermuteSubGLWETo computes ctOut -= ct0(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubGLWETo(ctOut GLWECiphertext[T], ct0 GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermuteSubPolyTo(ctOut.Value[i], ct0.Value[i], d)
	}
}
