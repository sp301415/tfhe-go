package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
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

// AddPlainLWE returns ct + pt.
func (e *Evaluator[T]) AddPlainLWE(ct LWECiphertext[T], pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.AddPlainLWETo(ctOut, ct, pt)
	return ctOut
}

// AddPlainLWETo computes ctOut = ct + pt.
func (e *Evaluator[T]) AddPlainLWETo(ctOut, ct LWECiphertext[T], pt LWEPlaintext[T]) {
	ctOut.CopyFrom(ct)
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

// SubPlainLWE returns ct - pt.
func (e *Evaluator[T]) SubPlainLWE(ct LWECiphertext[T], pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.SubPlainLWETo(ctOut, ct, pt)
	return ctOut
}

// SubPlainLWETo computes ctOut = ct0 - pt.
func (e *Evaluator[T]) SubPlainLWETo(ctOut, ct0 LWECiphertext[T], pt LWEPlaintext[T]) {
	ctOut.CopyFrom(ct0)
	ctOut.Value[0] -= pt.Value
}

// NegLWE returns -ct.
func (e *Evaluator[T]) NegLWE(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.NegLWETo(ctOut, ct)
	return ctOut
}

// NegLWETo computes ctOut = -ct.
func (e *Evaluator[T]) NegLWETo(ctOut, ct LWECiphertext[T]) {
	vec.NegTo(ctOut.Value, ct.Value)
}

// ScalarMulLWE returns c * ct.
func (e *Evaluator[T]) ScalarMulLWE(ct LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ScalarMulLWETo(ctOut, ct, c)
	return ctOut
}

// ScalarMulLWETo computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulLWETo(ctOut, ct LWECiphertext[T], c T) {
	vec.ScalarMulTo(ctOut.Value, ct.Value, c)
}

// ScalarMulAddLWETo computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddLWETo(ctOut, ct LWECiphertext[T], c T) {
	vec.ScalarMulAddTo(ctOut.Value, ct.Value, c)
}

// ScalarMulSubLWETo computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubLWETo(ctOut, ct LWECiphertext[T], c T) {
	vec.ScalarMulSubTo(ctOut.Value, ct.Value, c)
}
