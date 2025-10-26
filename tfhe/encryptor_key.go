package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// SecretKey is a structure containing LWE and GLWE key.
// All keys should be treated as read-only.
// Changing them mid-operation will usually result in wrong results.
//
// LWEKey and GLWEKey is sampled together, as explained in https://eprint.iacr.org/2023/958.
// As a result, LWEKey and GLWEKey share the same backing slice, so modifying one will affect the other.
type SecretKey[T TorusInt] struct {
	// LWELargeKey is a LWE key with length GLWEDimension.
	// Essentially, this is same as GLWEKey but parsed differently.
	LWELargeKey LWESecretKey[T]
	// GLWEKey is a key used for GLWE encryption and decryption.
	// Essentially, this is same as LWEKey but parsed differently.
	GLWEKey GLWESecretKey[T]
	// FFTGLWEKey is a fourier transformed GLWEKey.
	// Used for GLWE encryption.
	FFTGLWEKey FFTGLWESecretKey[T]
	// LWEKey is a LWE key with length LWEDimension.
	// Essentially, this is the first LWEDimension elements of LWEKey.
	LWEKey LWESecretKey[T]
}

// NewSecretKey creates a new SecretKey.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKey[T TorusInt](params Parameters[T]) SecretKey[T] {
	lweLargeKey := LWESecretKey[T]{Value: make([]T, params.glweDimension)}

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], params.glweRank)}
	for i := 0; i < params.glweRank; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*params.polyRank : (i+1)*params.polyRank]
	}
	FFTGLWEKey := NewFFTGLWESecretKey(params)

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:params.lweDimension]}

	return SecretKey[T]{
		LWELargeKey: lweLargeKey,
		GLWEKey:     glweKey,
		FFTGLWEKey:  FFTGLWEKey,
		LWEKey:      lweKey,
	}
}

// NewSecretKeyCustom creates a new SecretKey with given dimension and polyRank.
// Each key shares the same backing slice, held by LWEKey.
func NewSecretKeyCustom[T TorusInt](lweDimension, glweRank, polyRank int) SecretKey[T] {
	lweLargeKey := LWESecretKey[T]{Value: make([]T, glweRank*polyRank)}

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], glweRank)}
	for i := 0; i < glweRank; i++ {
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyRank : (i+1)*polyRank]
	}
	FFTGLWEKey := NewFFTGLWESecretKeyCustom[T](glweRank, polyRank)

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:lweDimension]}

	return SecretKey[T]{
		LWELargeKey: lweLargeKey,
		GLWEKey:     glweKey,
		FFTGLWEKey:  FFTGLWEKey,
		LWEKey:      lweKey,
	}
}

// Copy returns a copy of the key.
func (sk SecretKey[T]) Copy() SecretKey[T] {
	lweLargeKey := sk.LWELargeKey.Copy()

	glweKey := GLWESecretKey[T]{Value: make([]poly.Poly[T], len(sk.GLWEKey.Value))}
	for i := range glweKey.Value {
		polyRank := sk.GLWEKey.Value[i].Rank()
		glweKey.Value[i].Coeffs = lweLargeKey.Value[i*polyRank : (i+1)*polyRank]
	}
	FFTGLWEKey := sk.FFTGLWEKey.Copy()

	lweKey := LWESecretKey[T]{Value: lweLargeKey.Value[:len(sk.LWEKey.Value)]}

	return SecretKey[T]{
		LWELargeKey: lweLargeKey,
		GLWEKey:     glweKey,
		FFTGLWEKey:  FFTGLWEKey,
		LWEKey:      lweKey,
	}
}

// CopyFrom copies values from the key.
func (sk *SecretKey[T]) CopyFrom(skIn SecretKey[T]) {
	copy(sk.LWELargeKey.Value, skIn.LWELargeKey.Value)
	sk.FFTGLWEKey.CopyFrom(skIn.FFTGLWEKey)
}

// Clear clears the key.
func (sk *SecretKey[T]) Clear() {
	vec.Fill(sk.LWELargeKey.Value, 0)
	sk.FFTGLWEKey.Clear()
}

// PublicKey is a structure containing LWE and GLWE public key.
// All keys should be treated as read-only.
// Changing them mid-operation will usually result in wrong computation.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
type PublicKey[T TorusInt] struct {
	// LWEKey is a public key used for LWE encryption.
	// It is essentially a GLWE encryption of zero, but with reversed GLWE key,
	// as explained in https://eprint.iacr.org/2023/603.
	LWEKey LWEPublicKey[T]

	// GLWEKey is a public key used for LWE and GLWE encryption.
	// It is essentially a GLWE encryption of zero.
	GLWEKey GLWEPublicKey[T]
}

// NewPublicKey creates a new PublicKey.
//
// Panics when the parameters do not support public key encryption.
func NewPublicKey[T TorusInt](params Parameters[T]) PublicKey[T] {
	if !params.IsPublicKeyEncryptable() {
		panic("NewPublicKey: Parameters do not support public key encryption")
	}

	return PublicKey[T]{
		LWEKey:  NewLWEPublicKey(params),
		GLWEKey: NewGLWEPublicKey(params),
	}
}

// NewPublicKeyCustom creates a new PublicKey with given dimension and polyRank.
func NewPublicKeyCustom[T TorusInt](glweRank, polyRank int) PublicKey[T] {
	return PublicKey[T]{
		LWEKey:  NewLWEPublicKeyCustom[T](glweRank, polyRank),
		GLWEKey: NewGLWEPublicKeyCustom[T](glweRank, polyRank),
	}
}

// Copy returns a copy of the key.
func (pk PublicKey[T]) Copy() PublicKey[T] {
	return PublicKey[T]{
		LWEKey:  pk.LWEKey.Copy(),
		GLWEKey: pk.GLWEKey.Copy(),
	}
}

// CopyFrom copies values from the key.
func (pk *PublicKey[T]) CopyFrom(pkIn PublicKey[T]) {
	pk.LWEKey.CopyFrom(pkIn.LWEKey)
	pk.GLWEKey.CopyFrom(pkIn.GLWEKey)
}

// Clear clears the key.
func (pk *PublicKey[T]) Clear() {
	pk.LWEKey.Clear()
	pk.GLWEKey.Clear()
}
