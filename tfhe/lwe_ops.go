package tfhe

import (
	"github.com/sp301415/tfhe/math/vec"
)

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.AddInPlace(ct0.Value, ct1.Value, ctOut.Value)
}

// SubLWE subtracts ct0, ct1 and returns the result.
func (e Evaluater[T]) SubLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.SubLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubLWEInPlace subtracts ct0, ct1 and writes it to ctOut.
func (e Evaluater[T]) SubLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.SubInPlace(ct0.Value, ct1.Value, ctOut.Value)
}

// NegLWE negates ct0 and returns the result.
func (e Evaluater[T]) NegLWE(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NegLWEInPlace(ct0, ctOut)
	return ctOut
}

// NegLWEInPlace negates ct0 and writes it to ctOut.
func (e Evaluater[T]) NegLWEInPlace(ct0, ctOut LWECiphertext[T]) {
	vec.NegInPlace(ct0.Value, ctOut.Value)
}

// ScalarMulLWE multplies c to ct0 and returns the result.
func (e Evaluater[T]) ScalarMulLWE(ct0 LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ScalarMulLWEInPlace(ct0, c, ctOut)
	return ctOut
}

// ScalarMulLWEInPlace multplies c to ct0 and writes it to ctOut.
func (e Evaluater[T]) ScalarMulLWEInPlace(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulInPlace(ct0.Value, c, ctOut.Value)
}

// ScalarMulAddLWEInPlace multiplies c to ct1 and adds to ctOut.
func (e Evaluater[T]) ScalarMulAddLWEInPlace(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddInPlace(ct0.Value, c, ctOut.Value)
}

// ScalarMulSubLWEInPlace multiplies c to ct0 and subtracts from ctOut.
func (e Evaluater[T]) ScalarMulSubLWEInPlace(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubInPlace(ct0.Value, c, ctOut.Value)
}
