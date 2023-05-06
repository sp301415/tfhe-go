package tfhe

import "golang.org/x/exp/slices"

// LWESecretKey is a LWE secret key, sampled from uniform binary distribution.
type LWESecretKey[T Tint] struct {
	Value []T
}

// NewLWESecretKey allocates an empty LWESecretKey.
func NewLWESecretKey[T Tint](params Parameters[T]) LWESecretKey[T] {
	return LWESecretKey[T]{Value: make([]T, params.lweDimension)}
}

// Copy returns a copy of the key.
func (sk LWESecretKey[T]) Copy() LWESecretKey[T] {
	return LWESecretKey[T]{Value: slices.Clone(sk.Value)}
}

// Len returns the length of the key.
func (sk LWESecretKey[T]) Len() int {
	return len(sk.Value)
}

// LWEPlaintext represents an encoded LWE plaintext.
type LWEPlaintext[T Tint] struct {
	Value T
}

// Copy returns a copy of the plaintext.
func (pt LWEPlaintext[T]) Copy() LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: pt.Value}
}

// LWECiphertext represents an encrypted LWE ciphertext.
//
// LWE ciphertexts are the default encrypted form of the ciphertext.
type LWECiphertext[T Tint] struct {
	Mask []T
	Body T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	// mask is intentionally empty; defaults to zero value.
	return LWECiphertext[T]{Mask: make([]T, params.lweDimension)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{Mask: slices.Clone(ct.Mask), Body: ct.Body}
}

// Len returns the length of the ciphertext.
func (ct LWECiphertext[T]) Len() int {
	return len(ct.Mask) + 1
}
