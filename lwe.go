package tfhe

import "golang.org/x/exp/slices"

// LWESecretKey is a LWE secret key, sampled from uniform binary distribution.
type LWESecretKey[T Tint] struct {
	value []T
}

// NewLWESecretKey allocates an empty LWESecretKey.
func NewLWESecretKey[T Tint](params Parameters[T]) LWESecretKey[T] {
	return LWESecretKey[T]{value: make([]T, params.LWEDimension)}
}

// Copy returns a copy of the key.
func (sk LWESecretKey[T]) Copy() LWESecretKey[T] {
	return LWESecretKey[T]{value: slices.Clone(sk.value)}
}

// Len returns the length of the key.
func (sk LWESecretKey[T]) Len() int {
	return len(sk.value)
}

// LWEPlaintext represents an encoded LWE plaintext.
type LWEPlaintext[T Tint] struct {
	value T
}

// Copy returns a copy of the plaintext.
func (pt LWEPlaintext[T]) Copy() LWEPlaintext[T] {
	return LWEPlaintext[T]{value: pt.value}
}

// LWECiphertext represents an encrypted LWE ciphertext.
type LWECiphertext[T Tint] struct {
	value []T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{value: make([]T, params.LWEDimension+1)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{value: slices.Clone(ct.value)}
}

// Len returns the length of the ciphertext.
func (ct LWECiphertext[T]) Len() int {
	return len(ct.value)
}

// mask returns the first LWEDimension subslice of this ciphertext.
// This corresponds to the "a" part of the ciphertext.
func (ct LWECiphertext[T]) mask() []T {
	return ct.value[:ct.Len()-1]
}

// body returns the last element of this ciphertext.
// This corresponds to the "b" part of the ciphertext.
func (ct LWECiphertext[T]) body() T {
	return ct.value[ct.Len()-1]
}
