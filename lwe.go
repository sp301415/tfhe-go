package tfhe

import "golang.org/x/exp/slices"

// LWESecretKey is a LWE secret key, sampled from uniform binary distribution.
type LWESecretKey[T Tint] struct {
	body []T
}

// NewLWESecretKey allocates an empty LWESecretKey.
func NewLWESecretKey[T Tint](params Parameters[T]) LWESecretKey[T] {
	return LWESecretKey[T]{body: make([]T, params.LWEDimension)}
}

// Copy returns a copy of the key.
func (sk LWESecretKey[T]) Copy() LWESecretKey[T] {
	return LWESecretKey[T]{body: slices.Clone(sk.body)}
}

// Len returns the length of the key.
func (sk LWESecretKey[T]) Len() int {
	return len(sk.body)
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
	body []T
	mask T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	// mask is intentionally empty; defaults to zero value.
	return LWECiphertext[T]{body: make([]T, params.LWEDimension, params.LWEDimension+1)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{body: slices.Clone(ct.body), mask: ct.mask}
}

// Len returns the length of the ciphertext.
func (ct LWECiphertext[T]) Len() int {
	return len(ct.body) + 1
}

// asSlice returns the slice containing body + mask.
// This is intended to be read-only.
func (ct LWECiphertext[T]) asSlice() []T {
	return append(ct.body, ct.mask)
}
