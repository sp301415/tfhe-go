package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWEncryptor wraps around [tfhe.Encryptor] and implements FHEW encryption algorithm.
type FHEWEncryptor[T tfhe.TorusInt] struct {
	// Encryptor is an embedded [tfhe.Encryptor] for this FHEWEncryptor.
	*tfhe.Encryptor[T]

	// Parameters is the parameters for this FHEWEncryptor.
	Parameters FHEWParameters[T]

	buffer fhewEncryptionBuffer[T]
}

// fhewEncryptionBuffer is a buffer for FHEWEncryptor.
type fhewEncryptionBuffer[T tfhe.TorusInt] struct {
	// skPermute is the permuted secret key.
	skPermute tfhe.GLWESecretKey[T]
	// ctGLWE is the standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE tfhe.GLWECiphertext[T]
	// ptGGSW is GLWEKey * Pt in GGSW encryption.
	ptGGSW poly.Poly[T]
}

// NewFHEWEncryptor creates a new FHEWEncryptor with given parameters.
func NewFHEWEncryptor[T tfhe.TorusInt](params FHEWParameters[T]) *FHEWEncryptor[T] {
	encryptor := FHEWEncryptor[T]{
		Encryptor:  tfhe.NewEncryptorWithKey(params.BaseParameters(), tfhe.SecretKey[T]{}),
		Parameters: params,
		buffer:     newFHEWEncryptionBuffer(params),
	}
	encryptor.Encryptor.SecretKey = encryptor.GenSecretKey()

	return &encryptor
}

// NewFHEWEncryptorWithKey creates a new FHEWEncryptor with given parameters and secret key.
func NewFHEWEncryptorWithKey[T tfhe.TorusInt](params FHEWParameters[T], sk tfhe.SecretKey[T]) *FHEWEncryptor[T] {
	return &FHEWEncryptor[T]{
		Encryptor:  tfhe.NewEncryptorWithKey(params.BaseParameters(), sk),
		Parameters: params,
		buffer:     newFHEWEncryptionBuffer(params),
	}
}

// newFHEWEncryptionBuffer creates a new FHEWEncryptionBuffer with given parameters.
func newFHEWEncryptionBuffer[T tfhe.TorusInt](params FHEWParameters[T]) fhewEncryptionBuffer[T] {
	return fhewEncryptionBuffer[T]{
		skPermute: tfhe.NewGLWESecretKey(params.BaseParameters()),
		ctGLWE:    tfhe.NewGLWECiphertext(params.BaseParameters()),
		ptGGSW:    poly.NewPoly[T](params.BaseParameters().PolyDegree()),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *FHEWEncryptor[T]) ShallowCopy() *FHEWEncryptor[T] {
	return &FHEWEncryptor[T]{
		Encryptor:  e.Encryptor.ShallowCopy(),
		Parameters: e.Parameters,
		buffer:     newFHEWEncryptionBuffer(e.Parameters),
	}
}

// GenSecretKey samples a new SecretKey.
// The SecretKey of the Encryptor is not changed.
func (e *FHEWEncryptor[T]) GenSecretKey() tfhe.SecretKey[T] {
	sk := tfhe.NewSecretKey(e.Parameters.baseParameters)

	e.GaussianSampler.SampleVecAssign(e.Parameters.SecretKeyStdDevQ(), sk.LWELargeKey.Value)
	e.ToFourierGLWESecretKeyAssign(sk.GLWEKey, sk.FourierGLWEKey)

	return sk
}
