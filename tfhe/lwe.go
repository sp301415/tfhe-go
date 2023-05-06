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

	// Body is a pointer to T, not just T.
	// This is an ugly hack to match reference-copying behavior of GLWE, etc.
	Body *T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Mask: make([]T, params.lweDimension), Body: new(T)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	bodyCopy := *ct.Body
	return LWECiphertext[T]{Mask: slices.Clone(ct.Mask), Body: &bodyCopy}
}

// Len returns the length of the ciphertext.
func (ct LWECiphertext[T]) Len() int {
	return len(ct.Mask) + 1
}
