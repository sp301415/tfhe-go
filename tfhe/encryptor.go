package tfhe

import (
	"github.com/sp301415/tfhe/math/csprng"
	"github.com/sp301415/tfhe/math/poly"
)

// Encryptor encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
type Encryptor[T Tint] struct {
	Encoder[T]

	Parameters Parameters[T]

	uniformSampler csprng.UniformSampler[T]
	binarySampler  csprng.BinarySampler[T]
	blockSampler   csprng.BlockSampler[T]
	lweSampler     csprng.GaussianSampler[T]
	glweSampler    csprng.GaussianSampler[T]

	PolyEvaluator      poly.Evaluator[T]
	FourierTransformer poly.FourierTransformer[T]

	SecretKey SecretKey[T]

	buffer encryptionBuffer[T]
}

// encryptionBuffer contains buffer values for Encryptor.
type encryptionBuffer[T Tint] struct {
	// ctGLWE holds standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]
	// ptForGGSW holds GLWEKey * Pt in GGSW encryption.
	ptForGGSW poly.Poly[T]
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor[T Tint](params Parameters[T]) Encryptor[T] {
	// Fill samplers to call encryptor.GenSecretKey()
	encryptor := Encryptor[T]{
		Encoder: NewEncoder(params),

		Parameters: params,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		blockSampler:   csprng.NewBlockSampler[T](params.blockSize),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](params.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](params.glweStdDev),

		PolyEvaluator:      poly.NewEvaluator[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		buffer: newEncryptionBuffer(params),
	}

	// Generate Secret Key
	encryptor.SecretKey = encryptor.GenSecretKey()
	return encryptor
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T Tint](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ctGLWE:    NewGLWECiphertext(params),
		ptForGGSW: poly.New[T](params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e Encryptor[T]) ShallowCopy() Encryptor[T] {
	return Encryptor[T]{
		Encoder: e.Encoder,

		Parameters: e.Parameters,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](e.Parameters.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](e.Parameters.glweStdDev),

		SecretKey: e.SecretKey,

		PolyEvaluator:      e.PolyEvaluator.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}
