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
func (e *Evaluator[T]) ScalarMulLWE(c T, ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ScalarMulLWEAssign(c, ct0, ctOut)
	return ctOut
}

// ScalarMulLWEAssign computes ctOut = c * ct0.
func (e *Evaluator[T]) ScalarMulLWEAssign(c T, ct0, ctOut LWECiphertext[T]) {
	vec.ScalarMulAssign(c, ct0.Value, ctOut.Value)
}

// ScalarMulAddLWEAssign computes ctOut += c * ct0.
func (e *Evaluator[T]) ScalarMulAddLWEAssign(c T, ct0, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddAssign(c, ct0.Value, ctOut.Value)
}

// ScalarMulSubLWEAssign computes ctOut -= c * ct0.
func (e *Evaluator[T]) ScalarMulSubLWEAssign(c T, ct0, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubAssign(c, ct0.Value, ctOut.Value)
}
