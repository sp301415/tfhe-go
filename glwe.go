package tfhe

import (
	"github.com/sp301415/tfhe/internal/poly"
)

// GLWESecretKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWESecretKey[T Tint] struct {
	value []poly.Poly[T]
}

// NewGLWESecretKey allocates an empty GLWESecretKey.
func NewGLWESecretKey[T Tint](params Parameters[T]) GLWESecretKey[T] {
	polys := make([]poly.Poly[T], params.GLWEDimension)
	for i := range polys {
		polys[i] = poly.New[T](params.PolyDegree)
	}
	return GLWESecretKey[T]{value: polys}
}

// Copy returns a copy of the key.
func (sk GLWESecretKey[T]) Copy() GLWESecretKey[T] {
	polys := make([]poly.Poly[T], sk.Len())
	for i := range polys {
		polys[i] = sk.value[i].Copy()
	}
	return GLWESecretKey[T]{value: polys}
}

// Len returns the length of the key.
func (sk GLWESecretKey[T]) Len() int {
	return len(sk.value)
}

// Degree returns the polynomial degree of elements of the key.
func (sk GLWESecretKey[T]) Degree() int {
	return sk.value[0].Degree()
}

// ToLWESecretKey returns a new LWE secret key derived from the GLWE secret key.
func (sk GLWESecretKey[T]) ToLWESecretKey() LWESecretKey[T] {
	values := make([]T, sk.Len()*sk.Degree())
	for i := 0; i < sk.Len(); i++ {
		copy(values[i*sk.Degree():], sk.value[i].Coeffs)
	}
	return LWESecretKey[T]{value: values}
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T Tint] struct {
	value poly.Poly[T]
}

// Copy returns a copy of the plaintext.
func (pt GLWEPlaintext[T]) Copy() GLWEPlaintext[T] {
	return GLWEPlaintext[T]{value: pt.value.Copy()}
}

// GLWECiphertext represents an encrypted GLWE ciphertext.
type GLWECiphertext[T Tint] struct {
	value []poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T Tint](params Parameters[T]) GLWECiphertext[T] {
	polys := make([]poly.Poly[T], params.GLWEDimension+1)
	for i := range polys {
		polys[i] = poly.New[T](params.PolyDegree)
	}
	return GLWECiphertext[T]{value: polys}
}

// Copy returns a copy of the ciphertext.
func (ct GLWECiphertext[T]) Copy() GLWECiphertext[T] {
	polys := make([]poly.Poly[T], ct.Len())
	for i := range polys {
		polys[i] = ct.value[i].Copy()
	}
	return GLWECiphertext[T]{value: polys}
}

// Len returns the length of the ciphertext.
func (ct GLWECiphertext[T]) Len() int {
	return len(ct.value)
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct GLWECiphertext[T]) Degree() int {
	return ct.value[0].Degree()
}

// mask returns the first LWEDimension subslice of this ciphertext.
// This corresponds to the "a" part of the ciphertext.
func (ct GLWECiphertext[T]) mask() []poly.Poly[T] {
	return ct.value[:ct.Len()-1]
}

// body returns the last element of this ciphertext.
// This corresponds to the "b" part of the ciphertext.
func (ct GLWECiphertext[T]) body() poly.Poly[T] {
	return ct.value[ct.Len()-1]
}
