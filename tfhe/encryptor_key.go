package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// SecretKey is a structure containing LWE and GLWE key.
//
// LWEKey and GLWEKey is sampled together, as explained in https://eprint.iacr.org/2023/958.
// As a result, LWEKey and GLWEKey share the same backing slice, so modifying one will affect the other.
type SecretKey[T TorusInt] struct {
	// LWELargeKey is a LWE key with length LWELargeDimension.
	// Essentially, this is same as GLWEKey but parsed differently.
	LWELargeKey LWESecretKey[T]
	// GLWEKey is a key used for GLWE encryption and decryption.
	// Essentially, this is same as LWEKey but parsed differently.
	GLWEKey GLWESecretKey[T]
	// FourierGLWEKey is a fourier transformed GLWEKey.
	// Used for GLWE encryption.
	FourierGLWEKey FourierGLWESecretKey[T]
	// LWEKey is a LWE key with length LWEDimension.
	// Essentially, this is the first LWEDimension elements of LWEKey.
	LWEKey LWESecretKey[T]
}

// NewSecretKey allocates an empty SecretKey.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKey[T TorusInt](params Parameters[T]) SecretKey[T] {
	lweLargeKey := LWESecretKey[T]{Value: make([]T, params.lweLargeDimension)}

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], params.glweDimension)}
	for i := 0; i < params.glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*params.polyDegree : (i+1)*params.polyDegree]
	}
	fourierGLWEKey := NewFourierGLWESecretKey(params)

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:params.lweDimension]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// NewSecretKeyCustom allocates an empty SecretKey with given dimension and polyDegree.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKeyCustom[T TorusInt](lweDimension, glweDimension, polyDegree int) SecretKey[T] {
	lweLargeKey := LWESecretKey[T]{Value: make([]T, glweDimension*polyDegree)}

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], glweDimension)}
	for i := 0; i < glweDimension; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyDegree : (i+1)*polyDegree]
	}
	fourierGLWEKey := NewFourierGLWESecretKeyCustom[T](glweDimension, polyDegree)

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:lweDimension]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// Copy returns a copy of the key.
func (sk SecretKey[T]) Copy() SecretKey[T] {
	lweLargeKey := sk.LWELargeKey.Copy()

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], len(sk.GLWEKey.Value))}
	for i := range glweKey.Value {
		polyDegree := sk.GLWEKey.Value[i].Degree()
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyDegree : (i+1)*polyDegree]
	}
	fourierGLWEKey := sk.FourierGLWEKey.Copy()

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:len(sk.LWEKey.Value)]}

	return SecretKey[T]{
		LWELargeKey:    lweLargeKey,
		GLWEKey:        glweKey,
		FourierGLWEKey: fourierGLWEKey,
		LWEKey:         lweKey,
	}
}

// CopyFrom copies values from a key.
func (sk *SecretKey[T]) CopyFrom(skIn SecretKey[T]) {
	vec.CopyAssign(skIn.LWELargeKey.Value, sk.LWELargeKey.Value)
	sk.FourierGLWEKey.CopyFrom(skIn.FourierGLWEKey)
}

// Clear clears the key.
func (sk *SecretKey[T]) Clear() {
	vec.Fill(sk.LWELargeKey.Value, 0)
	sk.FourierGLWEKey.Clear()
}

// PublicKey is a structure containing LWE and GLWE public key.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
// Namely, DefaultLWEDimension should be power of two.
type PublicKey[T TorusInt] struct {
	// LWEPublicKey is a public key used for LWE encryption.
	// It is essentially a GLWE encryption of zero, but with reversed GLWE key,
	// as explained in https://eprint.iacr.org/2023/603.
	LWEPublicKey LWEPublicKey[T]

	// GLWEPublicKey is a public key used for LWE and GLWE encryption.
	// It is essentially a GLWE encryption of zero.
	GLWEPublicKey GLWEPublicKey[T]
}

// NewPublicKey allocates an empty PublicKey.
//
// Panics if DefaultLWEDimension is not power of two.
func NewPublicKey[T TorusInt](params Parameters[T]) PublicKey[T] {
	if !num.IsPowerOfTwo(params.DefaultLWEDimension()) {
		panic("Default LWE dimension not a power of two")
	}

	return PublicKey[T]{
		LWEPublicKey:  NewLWEPublicKey(params),
		GLWEPublicKey: NewGLWEPublicKey(params),
	}
}

// NewPublicKeyCustom allocates an empty PublicKey with given dimension and polyDegree.
//
// Panics if lweDimension is not power of two.
func NewPublicKeyCustom[T TorusInt](lweDimension, glweDimension, polyDegree int) PublicKey[T] {
	if !num.IsPowerOfTwo(lweDimension) {
		panic("LWE dimension not a power of two")
	}

	return PublicKey[T]{
		LWEPublicKey:  NewLWEPublicKeyCustom[T](lweDimension),
		GLWEPublicKey: NewGLWEPublicKeyCustom[T](glweDimension, polyDegree),
	}
}

// Copy returns a copy of the key.
func (pk PublicKey[T]) Copy() PublicKey[T] {
	return PublicKey[T]{
		LWEPublicKey:  pk.LWEPublicKey.Copy(),
		GLWEPublicKey: pk.GLWEPublicKey.Copy(),
	}
}

// CopyFrom copies values from a key.
func (pk *PublicKey[T]) CopyFrom(pkIn PublicKey[T]) {
	pk.LWEPublicKey.CopyFrom(pkIn.LWEPublicKey)
	pk.GLWEPublicKey.CopyFrom(pkIn.GLWEPublicKey)
}

// Clear clears the key.
func (pk *PublicKey[T]) Clear() {
	pk.LWEPublicKey.Clear()
	pk.GLWEPublicKey.Clear()
}
