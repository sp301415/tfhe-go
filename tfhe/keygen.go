package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
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
	// FourierGLWEKey is a fourier transformed GLWEKey.
	// Used for GLWE encryption.
	FourierGLWEKey []poly.FourierPoly
	// LWELargeKey is GLWE key parsed as LWE key.
	LWELargeKey LWEKey[T]
}

// NewSecretKey allocates an empty secret key.
// Each key shares the same backing slice, held by LWELargeKey.
func NewSecretKey[T Tint](params Parameters[T]) SecretKey[T] {
	lweLargeKey := LWEKey[T]{Value: make([]T, params.glweDimension*params.polyDegree)}

	lweKey := LWEKey[T]{Value: lweLargeKey.Value[:params.lweDimension]}

	glweKey := GLWEKey[T]{Value: make([]poly.Poly[T], params.glweDimension)}
	for i := 0; i < params.glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*params.polyDegree : (i+1)*params.polyDegree]
	}

	fourierGLWEKey := make([]poly.FourierPoly, params.glweDimension)
	for i := 0; i < params.glweDimension; i++ {
		fourierGLWEKey[i] = poly.NewFourierPoly(params.polyDegree)
	}

	return SecretKey[T]{
		LWEKey:         lweKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWELargeKey:    lweLargeKey,
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

	fourierGLWEKey := make([]poly.FourierPoly, len(sk.FourierGLWEKey))
	for i := range fourierGLWEKey {
		fourierGLWEKey[i] = sk.FourierGLWEKey[i].Copy()
	}

	return SecretKey[T]{
		LWEKey:         lweKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWELargeKey:    lweLargeKey,
	}
}

// CopyFrom copies values from a key.
func (sk *SecretKey[T]) CopyFrom(skIn SecretKey[T]) {
	vec.CopyAssign(skIn.LWELargeKey.Value, sk.LWELargeKey.Value)
	for i := range skIn.FourierGLWEKey {
		sk.FourierGLWEKey[i].CopyFrom(skIn.FourierGLWEKey[i])
	}
}

// Clear clears the key.
func (sk *SecretKey[T]) Clear() {
	vec.Fill(sk.LWELargeKey.Value, 0)
	for i := range sk.FourierGLWEKey {
		sk.FourierGLWEKey[i].Clear()
	}
}

// GenSecretKey samples a new LWE key.
func (e *Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Parameters)

	e.blockSampler.SampleSliceAssign(sk.LWELargeKey.Value[:e.Parameters.lweDimension])
	e.binarySampler.SampleSliceAssign(sk.LWELargeKey.Value[e.Parameters.lweDimension:])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.FourierEvaluator.ToFourierPolyAssign(sk.GLWEKey.Value[i], sk.FourierGLWEKey[i])
	}

	return sk
}
