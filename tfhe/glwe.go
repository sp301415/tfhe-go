package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// GLWESecretKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWESecretKey[T Tint] struct {
	Value []poly.Poly[T]
}

// NewGLWESecretKey allocates an empty GLWESecretKey.
func NewGLWESecretKey[T Tint](params Parameters[T]) GLWESecretKey[T] {
	sk := make([]poly.Poly[T], params.glweDimension)
	for i := range sk {
		sk[i] = poly.New[T](params.polyDegree)
	}
	return GLWESecretKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk GLWESecretKey[T]) Copy() GLWESecretKey[T] {
	skCopy := make([]poly.Poly[T], sk.Len())
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return GLWESecretKey[T]{Value: skCopy}
}

// Len returns the length of the key.
func (sk GLWESecretKey[T]) Len() int {
	return len(sk.Value)
}

// Degree returns the polynomial degree of elements of the key.
func (sk GLWESecretKey[T]) Degree() int {
	return sk.Value[0].Degree()
}

// ToLWESecretKey returns a new LWE secret key derived from the GLWE secret key.
func (sk GLWESecretKey[T]) ToLWESecretKey() LWESecretKey[T] {
	values := make([]T, sk.Len()*sk.Degree())
	for i := 0; i < sk.Len(); i++ {
		copy(values[i*sk.Degree():], sk.Value[i].Coeffs)
	}
	return LWESecretKey[T]{Value: values}
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T Tint] struct {
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

// Degree returns the polynomial degree of elements of the plaintext.
func (ct GLWEPlaintext[T]) Degree() int {
	return ct.Value.Degree()
}

// GLWECiphertext represents an encrypted GLWE ciphertext.
type GLWECiphertext[T Tint] struct {
	Mask []poly.Poly[T]
	Body poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T Tint](params Parameters[T]) GLWECiphertext[T] {
	mask := make([]poly.Poly[T], params.glweDimension)
	for i := range mask {
		mask[i] = poly.New[T](params.polyDegree)
	}
	return GLWECiphertext[T]{Mask: mask, Body: poly.New[T](params.polyDegree)}
}

// Copy returns a copy of the ciphertext.
func (ct GLWECiphertext[T]) Copy() GLWECiphertext[T] {
	maskCopy := make([]poly.Poly[T], ct.Len())
	for i := range maskCopy {
		maskCopy[i] = ct.Mask[i].Copy()
	}
	return GLWECiphertext[T]{Mask: maskCopy, Body: ct.Body.Copy()}
}

// Len returns the length of the ciphertext.
func (ct GLWECiphertext[T]) Len() int {
	return len(ct.Mask) + 1
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct GLWECiphertext[T]) Degree() int {
	return ct.Mask[0].Degree()
}
