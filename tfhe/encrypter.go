package tfhe

import (
	"github.com/sp301415/tfhe/math/csprng"
	"github.com/sp301415/tfhe/math/poly"
)

// Encrypter encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be a private only for clients.
//
// Encrypter uses fftw as backend, so manually freeing memory is needed.
// Use defer clause after initialization:
//
//	enc := tfhe.NewEncrypter(params)
//	defer enc.Free()
type Encrypter[T Tint] struct {
	Parameters Parameters[T]

	uniformSampler csprng.UniformSampler[T]
	binarySampler  csprng.BinarySampler[T]
	blockSampler   csprng.BlockSampler[T]
	lweSampler     csprng.GaussianSampler[T]
	glweSampler    csprng.GaussianSampler[T]

	PolyEvaluater      poly.Evaluater[T]
	FourierTransformer poly.FourierTransformer[T]

	SecretKey SecretKey[T]

	buffer encryptionBuffer[T]
}

// encryptionBuffer contains buffer values for Encrypter.
type encryptionBuffer[T Tint] struct {
	// standardCt holds standard GLWE Ciphertext for Fourier encryption / decryptions.
	standardCt GLWECiphertext[T]
	// ptForGGSW holds GLWEKey * Pt in GGSW encryption.
	ptForGGSW poly.Poly[T]
}

// NewEncrypter returns a initialized Encrypter with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	// Fill samplers to call encrypter.GenSecretKey()
	encrypter := Encrypter[T]{
		Parameters: params,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		blockSampler:   csprng.NewBlockSampler[T](params.blockSize),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](params.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](params.glweStdDev),

		PolyEvaluater:      poly.NewEvaluater[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		buffer: newEncryptionBuffer(params),
	}

	// Generate Secret Key
	encrypter.SecretKey = encrypter.GenSecretKey()
	return encrypter
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T Tint](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		standardCt: NewGLWECiphertext(params),
		ptForGGSW:  poly.New[T](params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this Encrypter.
// Returned Encrypter is safe for concurrent use.
func (e Encrypter[T]) ShallowCopy() Encrypter[T] {
	return Encrypter[T]{
		Parameters: e.Parameters,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](e.Parameters.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](e.Parameters.glweStdDev),

		SecretKey: e.SecretKey,

		PolyEvaluater:      e.PolyEvaluater.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}
