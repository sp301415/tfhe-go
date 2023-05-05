package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// GLWESecretKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWESecretKey[T Tint] struct {
	body []poly.Poly[T]
}

// NewGLWESecretKey allocates an empty GLWESecretKey.
func NewGLWESecretKey[T Tint](params Parameters[T]) GLWESecretKey[T] {
	polys := make([]poly.Poly[T], params.glweDimension)
	for i := range polys {
		polys[i] = poly.New[T](params.polyDegree)
	}
	return GLWESecretKey[T]{body: polys}
}

// Copy returns a copy of the key.
func (sk GLWESecretKey[T]) Copy() GLWESecretKey[T] {
	polys := make([]poly.Poly[T], sk.Len())
	for i := range polys {
		polys[i] = sk.body[i].Copy()
	}
	return GLWESecretKey[T]{body: polys}
}

// Len returns the length of the key.
func (sk GLWESecretKey[T]) Len() int {
	return len(sk.body)
}

// Degree returns the polynomial degree of elements of the key.
func (sk GLWESecretKey[T]) Degree() int {
	return sk.body[0].Degree()
}

// ToLWESecretKey returns a new LWE secret key derived from the GLWE secret key.
func (sk GLWESecretKey[T]) ToLWESecretKey() LWESecretKey[T] {
	values := make([]T, sk.Len()*sk.Degree())
	for i := 0; i < sk.Len(); i++ {
		copy(values[i*sk.Degree():], sk.body[i].Coeffs)
	}
	return LWESecretKey[T]{body: values}
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T Tint] struct {
	value poly.Poly[T]
}

// NewGLWEPlaintext allocates an empty GLWEPlaintext.
func NewGLWEPlaintext[T Tint](params Parameters[T]) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{value: poly.New[T](params.polyDegree)}
}

// Copy returns a copy of the plaintext.
func (pt GLWEPlaintext[T]) Copy() GLWEPlaintext[T] {
	return GLWEPlaintext[T]{value: pt.value.Copy()}
}

// GLWECiphertext represents an encrypted GLWE ciphertext.
type GLWECiphertext[T Tint] struct {
	body []poly.Poly[T]
	mask poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T Tint](params Parameters[T]) GLWECiphertext[T] {
	polys := make([]poly.Poly[T], params.glweDimension)
	for i := range polys {
		polys[i] = poly.New[T](params.polyDegree)
	}
	return GLWECiphertext[T]{body: polys, mask: poly.New[T](params.polyDegree)}
}

// Copy returns a copy of the ciphertext.
func (ct GLWECiphertext[T]) Copy() GLWECiphertext[T] {
	polys := make([]poly.Poly[T], ct.Len())
	for i := range polys {
		polys[i] = ct.body[i].Copy()
	}
	return GLWECiphertext[T]{body: polys, mask: ct.mask.Copy()}
}

// Len returns the length of the ciphertext.
func (ct GLWECiphertext[T]) Len() int {
	return len(ct.body) + 1
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct GLWECiphertext[T]) Degree() int {
	return ct.body[0].Degree()
}

// asSlice returns the slice containing body + mask.
// This is intended to be read-only.
func (ct GLWECiphertext[T]) asSlice() []poly.Poly[T] {
	return append(ct.body, ct.mask)
}
