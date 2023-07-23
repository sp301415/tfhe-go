package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// SecretKey is a structure containing LWE and GLWE key.
//
// LWEKey and GLWEKey is sampled together, as explained in https://eprint.iacr.org/2023/958.
// Therefore, values of LWEKey and GLWEKey are always assumed to be reslice of LWELargeKey.
type SecretKey[T Tint] struct {
	// LWEKey is a key used for LWE encryption and decryption.
	LWEKey LWEKey[T]
	// GLWEKey is a key used for GLWE encryption and decryption.
	GLWEKey GLWEKey[T]
	// LWELargeKey is GLWE key parsed as LWE key.
	LWELargeKey LWEKey[T]
}

// NewSecretKey allocates an empty secret key.
// Each key shares the same backing slice, held by LWELargeKey.
func NewSecretKey[T Tint](params Parameters[T]) SecretKey[T] {
	lweLargeKey := LWEKey[T]{Value: make([]T, params.glweDimension*params.polyDegree)}

	// Reslice first n elements to LWE key
	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:params.lweDimension]}

	// Reslice everything to GLWE key
	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], params.glweDimension)}
	for i := 0; i < params.glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*params.polyDegree : (i+1)*params.polyDegree]
	}

	return SecretKey[T]{
		LWEKey:      lweKey,
		GLWEKey:     glweKey,
		LWELargeKey: lweLargeKey,
	}
}

// Copy returns a copy of the key.
func (sk SecretKey[T]) Copy() SecretKey[T] {
	lweLargeKey := LWEKey[T]{Value: vec.Copy(sk.LWELargeKey.Value)}

	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:len(sk.LWEKey.Value)]}

	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], len(sk.GLWEKey.Value))}
	for i := range glweKey.Value {
		degree := sk.GLWEKey.Value[i].Degree()
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*degree : (i+1)*degree]
	}

	return SecretKey[T]{
		LWEKey:      lweKey,
		GLWEKey:     glweKey,
		LWELargeKey: lweLargeKey,
	}
}

// CopyFrom copies values from a key.
func (sk *SecretKey[T]) CopyFrom(skIn SecretKey[T]) {
	vec.CopyInPlace(skIn.LWELargeKey.Value, sk.LWELargeKey.Value)
}

// GenSecretKey samples a new LWE key.
func (e Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Parameters)

	// Sample LWE key from Block Binary Distribution
	e.blockSampler.SampleSliceInPlace(sk.LWELargeKey.Value[:e.Parameters.lweDimension])

	// Sample the rest from Binary Distribution
	e.binarySampler.SampleSliceInPlace(sk.LWELargeKey.Value[e.Parameters.lweDimension:])

	return sk
}
