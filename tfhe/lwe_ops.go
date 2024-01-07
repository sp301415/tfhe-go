package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// AddLWE adds two LWE cipheretexts ct0, ct1.
func (e *Evaluator[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEAssign adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e *Evaluator[T]) AddLWEAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.AddAssign(ct0.Value, ct1.Value, ctOut.Value)
}

// SubLWE subtracts ct0, ct1.
func (e *Evaluator[T]) SubLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.SubLWEAssign(ct0, ct1, ctOut)
	return ctOut
}

// SubLWEAssign subtracts ct0, ct1 and writes it to ctOut.
func (e *Evaluator[T]) SubLWEAssign(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.SubAssign(ct0.Value, ct1.Value, ctOut.Value)
}

// NegLWE negates ct0.
func (e *Evaluator[T]) NegLWE(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NegLWEAssign(ct0, ctOut)
	return ctOut
}

// NegLWEAssign negates ct0 and writes it to ctOut.
func (e *Evaluator[T]) NegLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.NegAssign(ct0.Value, ctOut.Value)
}

// PlaintextAddLWE adds pt to ct0.
func (e *Evaluator[T]) PlaintextAddLWE(ct0 LWECiphertext[T], pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.PlaintextAddLWEAssign(ct0, pt, ctOut)
	return ctOut
}

// PlaintextAddLWEAssign adds pt to ct0 and writes it to ctOut.
func (e *Evaluator[T]) PlaintextAddLWEAssign(ct0 LWECiphertext[T], pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] += pt.Value
}

// ScalarMulLWE multiplies c to ct0.
func (e *Evaluator[T]) ScalarMulLWE(ct0 LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ScalarMulLWEAssign(ct0, c, ctOut)
	return ctOut
}

// ScalarMulLWEAssign multiplies c to ct0 and writes it to ctOut.
func (e *Evaluator[T]) ScalarMulLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulAddLWEAssign multiplies c to ct1 and adds to ctOut.
func (e *Evaluator[T]) ScalarMulAddLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulSubLWEAssign multiplies c to ct0 and subtracts from ctOut.
func (e *Evaluator[T]) ScalarMulSubLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubAssign(ct0.Value, c, ctOut.Value)
}
