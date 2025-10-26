package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// AddLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.AddLWETo(ctOut, ct0, ct1)
	return ctOut
}

// AddLWETo computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddLWETo(ctOut, ct0, ct1 LWECiphertext[T]) {
	vec.AddTo(ctOut.Value, ct0.Value, ct1.Value)
}

// AddPlainLWE returns ct0 + pt.
func (e *Evaluator[T]) AddPlainLWE(ct0 LWECiphertext[T], pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.AddPlainLWETo(ctOut, ct0, pt)
	return ctOut
}

// AddPlainLWETo computes ctOut = ct0 + pt.
func (e *Evaluator[T]) AddPlainLWETo(ctOut LWECiphertext[T], ct0 LWECiphertext[T], pt tfhe.LWEPlaintext[T]) {
	ctOut.CopyFrom(ct0)
	ctOut.Value[0] += pt.Value
}

// SubLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.SubLWETo(ctOut, ct0, ct1)
	return ctOut
}

// SubLWETo computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubLWETo(ctOut, ct0, ct1 LWECiphertext[T]) {
	vec.SubTo(ctOut.Value, ct0.Value, ct1.Value)
}

// SubPlainLWE returns ct0 - pt.
func (e *Evaluator[T]) SubPlainLWE(ct0 LWECiphertext[T], pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.SubPlainLWETo(ctOut, ct0, pt)
	return ctOut
}

// SubPlainLWETo computes ctOut = ct0 - pt.
func (e *Evaluator[T]) SubPlainLWETo(ctOut LWECiphertext[T], ct0 LWECiphertext[T], pt tfhe.LWEPlaintext[T]) {
	ctOut.CopyFrom(ct0)
	ctOut.Value[0] -= pt.Value
}

// NegLWE returns -ct0.
func (e *Evaluator[T]) NegLWE(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NegLWETo(ctOut, ct0)
	return ctOut
}

// NegLWETo computes ctOut = -ct0.
func (e *Evaluator[T]) NegLWETo(ctOut, ct0 LWECiphertext[T]) {
	vec.NegTo(ctOut.Value, ct0.Value)
}

// ScalarMulLWE returns c * ct0.
func (e *Evaluator[T]) ScalarMulLWE(ct0 LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ScalarMulLWETo(ctOut, ct0, c)
	return ctOut
}

// ScalarMulLWETo computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulLWETo(ctOut LWECiphertext[T], ct0 LWECiphertext[T], c T) {
	vec.ScalarMulTo(ctOut.Value, ct0.Value, c)
}

// ScalarMulAddLWETo computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddLWETo(ctOut LWECiphertext[T], ct0 LWECiphertext[T], c T) {
	vec.ScalarMulAddTo(ctOut.Value, ct0.Value, c)
}

// ScalarMulSubLWETo computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubLWETo(ctOut LWECiphertext[T], ct0 LWECiphertext[T], c T) {
	vec.ScalarMulSubTo(ctOut.Value, ct0.Value, c)
}
