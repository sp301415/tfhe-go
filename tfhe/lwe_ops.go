package tfhe

import "github.com/sp301415/tfhe/math/vec"

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
