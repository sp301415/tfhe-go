package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// GLWEKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWEKey[T Tint] struct {
	// Value has length GLWEDimension.
	Value []poly.Poly[T]
}

// NewGLWEKey allocates an empty GLWESecretKey.
func NewGLWEKey[T Tint](params Parameters[T]) GLWEKey[T] {
	sk := make([]poly.Poly[T], params.glweDimension)
	for i := range sk {
		sk[i] = poly.New[T](params.polyDegree)
	}
	return GLWEKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk GLWEKey[T]) Copy() GLWEKey[T] {
	skCopy := make([]poly.Poly[T], len(sk.Value))
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return GLWEKey[T]{Value: skCopy}
}

// ToLWEKey returns a new LWE secret key derived from the GLWE secret key.
func (sk GLWEKey[T]) ToLWEKey() LWEKey[T] {
	glweDimension := len(sk.Value)
	degree := sk.Value[0].Degree()

	lweKey := LWEKey[T]{Value: make([]T, glweDimension*degree)}
	for i := 0; i < glweDimension; i++ {
		copy(lweKey.Value[i*degree:], sk.Value[i].Coeffs)
	}
	return lweKey
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T Tint] struct {
	// Value is a single polynomial.
	Value poly.Poly[T]
}

// NewGLWEPlaintext allocates an empty GLWEPlaintext.
func NewGLWEPlaintext[T Tint](params Parameters[T]) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.New[T](params.polyDegree)}
}

// Copy returns a copy of the plaintext.
func (pt GLWEPlaintext[T]) Copy() GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: pt.Value.Copy()}
}

// GLWECiphertext represents an encrypted GLWE ciphertext.
type GLWECiphertext[T Tint] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWEDimension + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T Tint](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = poly.New[T](params.polyDegree)
	}
	return GLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct GLWECiphertext[T]) Copy() GLWECiphertext[T] {
	ctCopy := make([]poly.Poly[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GLWECiphertext[T]{Value: ctCopy}
}

// GLevCiphertext is a leveled GLWE ciphertext, decomposed according to DecompositionParameters.
type GLevCiphertext[T Tint] struct {
	// Value has length Level.
	Value []GLWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGLevCiphertext allocates an empty GLevCiphertext.
func NewGLevCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		ct[i] = NewGLWECiphertext(params)
	}
	return GLevCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct GLevCiphertext[T]) Copy() GLevCiphertext[T] {
	ctCopy := make([]GLWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GLevCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct GLevCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
