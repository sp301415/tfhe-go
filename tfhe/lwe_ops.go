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

// AddLWEAssign adds LWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.AddAssign(ct0.Value, ctOut.Value)
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

// SubLWEAssign subtracts ct0 from ctOut.
func (e Evaluater[T]) SubLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.SubAssign(ct0.Value, ctOut.Value)
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

// NegLWEAssign negates ct0.
func (e Evaluater[T]) NegLWEAssign(ct0 LWECiphertext[T]) {
	vec.NegAssign(ct0.Value)
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

// ScalarMulLWEAssign multplies c to ctOut.
func (e Evaluater[T]) ScalarMulLWEAssign(c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAssign(c, ctOut.Value)
}

// ScalarMulAddLWEAssign multiplies c to ct1 and adds to ctOut.
func (e Evaluater[T]) ScalarMulAddLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulSubLWEAssign multiplies c to ct0 and subtracts from ctOut.
func (e Evaluater[T]) ScalarMulSubLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubAssign(ct0.Value, c, ctOut.Value)
}
