package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// AddLWE returns ct0 + ct1.
func (e *Evaluator[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEAssign computes ctOut = ct0 + ct1.
func (e *Evaluator[T]) AddLWEAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.AddAssign(ct0.Value, ct1.Value, ctOut.Value)
}

// AddPlainLWE returns ct0 + pt.
func (e *Evaluator[T]) AddPlainLWE(ct0 LWECiphertext[T], pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddPlainLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// AddPlainLWEAssign computes ctOut = ct0 + pt.
func (e *Evaluator[T]) AddPlainLWEAssign(ct0 LWECiphertext[T], pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	ctOut.Value[0] += pt.Value
}

// SubLWE returns ct0 - ct1.
func (e *Evaluator[T]) SubLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.SubLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubLWEAssign computes ctOut = ct0 - ct1.
func (e *Evaluator[T]) SubLWEAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.SubAssign(ct0.Value, ct1.Value, ctOut.Value)
}

// SubPlainLWE returns ct0 - pt.
func (e *Evaluator[T]) SubPlainLWE(ct0 LWECiphertext[T], pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.SubPlainLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// SubPlainLWEAssign computes ctOut = ct0 - pt.
func (e *Evaluator[T]) SubPlainLWEAssign(ct0 LWECiphertext[T], pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] -= pt.Value
}

// NegLWE returns -ct0.
func (e *Evaluator[T]) NegLWE(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NegLWEAssign(ct0, ctOut)
	return ctOut
}

// NegLWEAssign computes ctOut = -ct0.
func (e *Evaluator[T]) NegLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.NegAssign(ct0.Value, ctOut.Value)
}

// PlaintextAddLWE returns pt + ct0.
func (e *Evaluator[T]) PlaintextAddLWE(pt LWEPlaintext[T], ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PlaintextAddLWEAssign(pt, ct0, ctOut)
	return ctOut
}

// PlaintextAddLWEAssign computes ctOut = pt + ct0.
func (e *Evaluator[T]) PlaintextAddLWEAssign(pt LWEPlaintext[T], ct0, ctOut LWECiphertext[T]) {
	ctOut.Value[0] += pt.Value
}

// ScalarMulLWE returns c * ct0.
func (e *Evaluator[T]) ScalarMulLWE(ct0 LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ScalarMulLWEAssign(ct0, c, ctOut)
	return ctOut
}

// ScalarMulLWEAssign computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulAddLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulSubLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubAssign(ct0.Value, c, ctOut.Value)
}
