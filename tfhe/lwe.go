package tfhe

import "github.com/sp301415/tfhe/math/vec"

// LWEKey is a LWE secret key, sampled from uniform binary distribution.
type LWEKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []T
}

// NewLWEKey allocates an empty LWESecretKey.
func NewLWEKey[T Tint](params Parameters[T]) LWEKey[T] {
	return LWEKey[T]{Value: make([]T, params.lweDimension)}
}

// Copy returns a copy of the key.
func (sk LWEKey[T]) Copy() LWEKey[T] {
	return LWEKey[T]{Value: vec.Copy(sk.Value)}
}

// LWEPlaintext represents an encoded LWE plaintext.
type LWEPlaintext[T Tint] struct {
	// Value is a scalar.
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
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length LWEDimension + 1.
	Value []T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, params.lweDimension+1)}
}

// NewLargeLWECiphertext allocates an empty LWECiphertext,
// but with dimension GLWEDimension * PolyDegree + 1.
func NewLargeLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, params.glweDimension*params.polyDegree+1)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{Value: vec.Copy(ct.Value)}
}

// LevCiphertext is a leveled LWE ciphertext, decomposed according to DecompositionParameters.
type LevCiphertext[T Tint] struct {
	// Value has length Level.
	Value []LWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewLevCiphertext allocates an empty LevCiphertext.
func NewLevCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) LevCiphertext[T] {
	ct := make([]LWECiphertext[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		ct[i] = NewLWECiphertext(params)
	}
	return LevCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct LevCiphertext[T]) Copy() LevCiphertext[T] {
	ctCopy := make([]LWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return LevCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct LevCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
