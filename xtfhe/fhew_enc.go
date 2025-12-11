package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWEncryptor wraps around [tfhe.Encryptor] and implements FHEW encryption algorithm.
type FHEWEncryptor[T tfhe.TorusInt] struct {
	// Encryptor is an embedded [tfhe.Encryptor] for this FHEWEncryptor.
	*tfhe.Encryptor[T]

	// Params is parameters for this FHEWEncryptor.
	Params FHEWParameters[T]

	buf fhewEncryptorBuffer[T]
}

// fhewEncryptorBuffer is a buffer for FHEWEncryptor.
type fhewEncryptorBuffer[T tfhe.TorusInt] struct {
	// skPermute is a permuted secret key.
	skPermute tfhe.GLWESecretKey[T]
	// ctGLWE is a standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE tfhe.GLWECiphertext[T]
	// ptGGSW is GLWEKey * Pt in GGSW encryption.
	ptGGSW poly.Poly[T]
}

// NewFHEWEncryptor creates a new FHEWEncryptor.
func NewFHEWEncryptor[T tfhe.TorusInt](params FHEWParameters[T]) *FHEWEncryptor[T] {
	encryptor := FHEWEncryptor[T]{
		Encryptor: tfhe.NewEncryptorWithKey(params.BaseParams(), tfhe.SecretKey[T]{}),
		Params:    params,
		buf:       newFHEWEncryptorBuffer(params),
	}
	encryptor.Encryptor.SecretKey = encryptor.GenSecretKey()

	return &encryptor
}

// NewFHEWEncryptorWithKey creates a new FHEWEncryptor with given parameters and secret key.
func NewFHEWEncryptorWithKey[T tfhe.TorusInt](params FHEWParameters[T], sk tfhe.SecretKey[T]) *FHEWEncryptor[T] {
	return &FHEWEncryptor[T]{
		Encryptor: tfhe.NewEncryptorWithKey(params.BaseParams(), sk),
		Params:    params,
		buf:       newFHEWEncryptorBuffer(params),
	}
}

// newFHEWEncryptorBuffer creates a new fhewEncryptorBuffer.
func newFHEWEncryptorBuffer[T tfhe.TorusInt](params FHEWParameters[T]) fhewEncryptorBuffer[T] {
	return fhewEncryptorBuffer[T]{
		skPermute: tfhe.NewGLWESecretKey(params.BaseParams()),
		ctGLWE:    tfhe.NewGLWECiphertext(params.BaseParams()),
		ptGGSW:    poly.NewPoly[T](params.BaseParams().PolyRank()),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *FHEWEncryptor[T]) SafeCopy() *FHEWEncryptor[T] {
	return &FHEWEncryptor[T]{
		Encryptor: e.Encryptor.SafeCopy(),
		Params:    e.Params,
		buf:       newFHEWEncryptorBuffer(e.Params),
	}
}

// GenSecretKey samples a new SecretKey.
// The SecretKey of the Encryptor is not changed.
func (e *FHEWEncryptor[T]) GenSecretKey() tfhe.SecretKey[T] {
	sk := tfhe.NewSecretKey(e.Params.baseParams)

	e.GaussianSampler.SampleVecTo(sk.LWELargeKey.Value, e.Params.SecretKeyStdDevQ())
	e.FwdFFTGLWESecretKeyTo(sk.FFTGLWEKey, sk.GLWEKey)

	return sk
}
