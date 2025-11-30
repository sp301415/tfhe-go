package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// AddFFTGLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddFFTGLWE(ct0, ct1 FFTGLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.AddFFTGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// AddFFTGLWETo computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddFFTGLWETo(ctOut, ct0, ct1 FFTGLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.AddFFTPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// SubFFTGLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubFFTGLWE(ct0, ct1 FFTGLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.SubFFTGLWETo(ctOut, ct0, ct1)
	return ctOut
}

// SubFFTGLWETo computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubFFTGLWETo(ctOut, ct0, ct1 FFTGLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.SubFFTPolyTo(ctOut.Value[i], ct0.Value[i], ct1.Value[i])
	}
}

// NegFFTGLWE returns -ct.
func (e *Evaluator[T]) NegFFTGLWE(ct FFTGLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.NegFFTGLWETo(ctOut, ct)
	return ctOut
}

// NegFFTGLWETo computes ctOut = -ct.
func (e *Evaluator[T]) NegFFTGLWETo(ctOut, ct FFTGLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.NegFFTPolyTo(ctOut.Value[i], ct.Value[i])
	}
}

// FloatMulFFTGLWE returns c * ct.
func (e *Evaluator[T]) FloatMulFFTGLWE(ct FFTGLWECiphertext[T], c float64) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.FloatMulFFTGLWETo(ctOut, ct, c)
	return ctOut
}

// FloatMulFFTGLWETo computes ctOut = c * ct.
func (e *Evaluator[T]) FloatMulFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c float64) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FloatMulFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// FloatMulAddFFTGLWETo computes ctOut += c * ct.
func (e *Evaluator[T]) FloatMulAddFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c float64) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FloatMulAddFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// FloatMulSubFFTGLWETo computes ctOut -= c * ct.
func (e *Evaluator[T]) FloatMulSubFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c float64) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.FloatMulSubFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// CmplxMulFFTGLWE returns c * ct0.
func (e *Evaluator[T]) CmplxMulFFTGLWE(ct FFTGLWECiphertext[T], c complex128) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.CmplxMulFFTGLWETo(ctOut, ct, c)
	return ctOut
}

// CmplxMulFFTGLWETo computes ctOut = c * ct.
func (e *Evaluator[T]) CmplxMulFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c complex128) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.CmplxMulFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// CmplxMulAddFFTGLWETo computes ctOut += c * ct.
func (e *Evaluator[T]) CmplxMulAddFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c complex128) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.CmplxMulAddFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// CmplxMulSubFFTGLWETo computes ctOut -= c * ct.
func (e *Evaluator[T]) CmplxMulSubFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], c complex128) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.CmplxMulSubFFTPolyTo(ctOut.Value[i], ct.Value[i], c)
	}
}

// PolyMulFFTGLWE returns p * ct.
func (e *Evaluator[T]) PolyMulFFTGLWE(ct FFTGLWECiphertext[T], p poly.Poly[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.PolyMulFFTGLWETo(ctOut, ct, p)
	return ctOut
}

// PolyMulFFTGLWETo computes ctOut = p * ct.
func (e *Evaluator[T]) PolyMulFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], p poly.Poly[T]) {
	e.PolyEvaluator.FwdFFTPolyTo(e.buf.fpMul, p)
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulFFTPolyTo(ctOut.Value[i], ct.Value[i], e.buf.fpMul)
	}
}

// PolyMulAddFFTGLWETo computes ctOut += p * ct.
func (e *Evaluator[T]) PolyMulAddFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], p poly.Poly[T]) {
	e.PolyEvaluator.FwdFFTPolyTo(e.buf.fpMul, p)
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulAddFFTPolyTo(ctOut.Value[i], ct.Value[i], e.buf.fpMul)
	}
}

// PolyMulSubFFTGLWETo computes ctOut -= p * ct.
func (e *Evaluator[T]) PolyMulSubFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], p poly.Poly[T]) {
	e.PolyEvaluator.FwdFFTPolyTo(e.buf.fpMul, p)
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulSubFFTPolyTo(ctOut.Value[i], ct.Value[i], e.buf.fpMul)
	}
}

// FFTPolyMulFFTGLWE returns fp * ct.
func (e *Evaluator[T]) FFTPolyMulFFTGLWE(ct FFTGLWECiphertext[T], fp poly.FFTPoly) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.FFTPolyMulFFTGLWETo(ctOut, ct, fp)
	return ctOut
}

// FFTPolyMulFFTGLWETo computes ctOut = fp * ct.
func (e *Evaluator[T]) FFTPolyMulFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulFFTPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulAddFFTGLWETo computes ctOut += fp * ct.
func (e *Evaluator[T]) FFTPolyMulAddFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulAddFFTPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// FFTPolyMulSubFFTGLWETo computes ctOut -= fp * ct.
func (e *Evaluator[T]) FFTPolyMulSubFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], fp poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.MulSubFFTPolyTo(ctOut.Value[i], ct.Value[i], fp)
	}
}

// PermuteFFTGLWE returns ctOut = ct(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTGLWE(ct FFTGLWECiphertext[T], d int) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.PermuteFFTGLWETo(ctOut, ct, d)
	return ctOut
}

// PermuteFourierTo computes ctOut = ct(X^d).
//
// ct and ctOut should not overlap. For inplace permutation,
// use [*Evaluator.PermuteFFTGLWEInPlace].
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteFFTPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteGLWEInPlace computes ct = ct(X^d).
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteFFTGLWEInPlace(ct FFTGLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteFFTPolyInPlace(ct.Value[i], d)
	}
}

// PermuteAddFFTGLWETo computes ctOut += ct(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteAddFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteAddFFTPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}

// PermuteSubFFTGLWETo computes ctOut -= ct(X^d).
//
// ct0 and ctOut should not overlap.
//
// Panics when d is not odd.
// This is because the permutation is not bijective when d is even.
func (e *Evaluator[T]) PermuteSubFFTGLWETo(ctOut, ct FFTGLWECiphertext[T], d int) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.PermuteSubFFTPolyTo(ctOut.Value[i], ct.Value[i], d)
	}
}
