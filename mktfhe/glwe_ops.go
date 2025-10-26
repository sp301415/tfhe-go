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

// AddPlainGLWE returns ct + pt.
func (e *Evaluator[T]) AddPlainGLWE(ct GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.AddPlainGLWETo(ctOut, ct, pt)
	return ctOut
}

// AddPlainGLWETo computes ctOut = ct + pt.
func (e *Evaluator[T]) AddPlainGLWETo(ctOut, ct GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	for i := 1; i < e.Params.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(ct.Value[i])
	}
	e.subEvaluator.PolyEvaluator.AddPolyTo(ctOut.Value[0], ct.Value[0], pt.Value)
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

// SubPlainGLWE returns ct - pt.
func (e *Evaluator[T]) SubPlainGLWE(ct GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.SubPlainGLWETo(ctOut, ct, pt)
	return ctOut
}

// SubPlainGLWETo computes ctOut = ct - pt.
func (e *Evaluator[T]) SubPlainGLWETo(ctOut, ct GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	for i := 1; i < e.Params.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(ct.Value[i])
	}
	e.subEvaluator.PolyEvaluator.SubPolyTo(ctOut.Value[0], ct.Value[0], pt.Value)
}

// NegGLWE returns -ct0.
func (e *Evaluator[T]) NegGLWE(ct GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.NegGLWETo(ctOut, ct)
	return ctOut
}

// NegGLWETo computes ctOut = -ct0.
func (e *Evaluator[T]) NegGLWETo(ctOut, ct GLWECiphertext[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.NegPolyTo(ctOut.Value[i], ct.Value[i])
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
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// ScalarMulAddGLWETo computes ctOut += c * ct.
func (e *Evaluator[T]) ScalarMulAddGLWETo(ctOut, ct GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulAddPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// ScalarMulSubGLWETo computes ctOut -= c * ct.
func (e *Evaluator[T]) ScalarMulSubGLWETo(ctOut, ct GLWECiphertext[T], c T) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.ScalarMulSubPolyTo(ctOut.Value[i], ct.Value[i], c)
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
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulPolyTo(ctOut.Value[i], ct.Value[i], p)
	}
}

// PolyMulAddGLWETo computes ctOut += p * ct.
func (e *Evaluator[T]) PolyMulAddGLWETo(ctOut, ct GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulAddPolyTo(ctOut.Value[i], ct.Value[i], p)
	}
}

// PolyMulSubGLWETo computes ctOut -= p * ct.
func (e *Evaluator[T]) PolyMulSubGLWETo(ctOut, ct GLWECiphertext[T], p poly.Poly[T]) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MulSubPolyTo(ctOut.Value[i], ct.Value[i], p)
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
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.FFTPolyMulPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulAddGLWETo computes ctOut += fp * ct.
func (e *Evaluator[T]) FFTPolyMulAddGLWETo(ctOut, ct GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.FFTPolyMulAddPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulSubGLWETo computes ctOut -= fp * ct.
func (e *Evaluator[T]) FFTPolyMulSubGLWETo(ctOut, ct GLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
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
// ct and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// MonomialMulGLWEInPlace computes ct0 = X^d * ct.
func (e *Evaluator[T]) MonomialMulGLWEInPlace(ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulPolyInPlace(ct.Value[i], d)
	}
}

// MonomialMulAddGLWETo computes ctOut += X^d * ct.
//
// ct and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulAddGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulAddPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// MonomialMulSubGLWETo computes ctOut -= X^d * ct.
//
// ct and ctOut should not overlap.
func (e *Evaluator[T]) MonomialMulSubGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.subEvaluator.PolyEvaluator.MonomialMulSubPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteGLWETo computes ctOut = ct(X^d).
//
// ct and ctOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteGLWEInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWETo(ctOut, ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermutePolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteGLWEInPlace computes ct0 = ct(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteGLWEInPlace(ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermutePolyInPlace(ct.Value[i], d)
	}
}

// PermuteAddGLWETo computes ctOut += ct(X^d).
//
// ct and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddGLWETo(ctOut GLWECiphertext[T], ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermuteAddPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteSubGLWETo computes ctOut -= ct(X^d).
//
// ct and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubGLWETo(ctOut GLWECiphertext[T], ct GLWECiphertext[T], d int) {
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.PermuteSubPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}
