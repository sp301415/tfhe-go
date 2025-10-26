package tfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
)

// PublicEncryptor encrypts TFHE ciphertexts with public key.
// This is meant to be public, usually for servers.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
//
// PublicEncryptor is not safe for concurrent use.
// Use [*PublicEncryptor.SafeCopy] to get a safe copy.
type PublicEncryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this PublicEncryptor.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this PublicEncryptor.
	*GLWETransformer[T]

	// Params is the parameters for this PublicEncryptor.
	Params Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler *csprng.UniformSampler[T]
	// BinarySampler is used for sampling the auxiliary "key" in encryptions.
	BinarySampler *csprng.BinarySampler[T]
	// GaussianSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler *csprng.GaussianSampler[T]

	// PolyEvaluator is a PolyEvaluator for this PublicEncryptor.
	PolyEvaluator *poly.Evaluator[T]

	// PublicKey is the public key for this PublicEncryptor.
	PublicKey PublicKey[T]

	buf publicEncryptorBuffer[T]
}

// publicEncryptorBuffer is a buffer for PublicEncryptor.
type publicEncryptorBuffer[T TorusInt] struct {
	// ptGLWE is the GLWE plaintext for GLWE encryption / decryptions.
	ptGLWE GLWEPlaintext[T]
	// ctGLWE is the standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]

	// auxKey is the auxiliary key for encryption.
	// This must be sampled fresh for each encryption.
	auxKey GLWESecretKey[T]
	// auxFourierKey is the fourier transform of auxKey.
	auxFourierKey FFTGLWESecretKey[T]
}

// NewPublicEncryptor creates a new PublicEncryptor.
//
// Panics when the parameters do not support public key encryption.
func NewPublicEncryptor[T TorusInt](params Parameters[T], pk PublicKey[T]) *PublicEncryptor[T] {
	if !params.IsPublicKeyEncryptable() {
		panic("Parameters do not support public key encryption")
	}

	return &PublicEncryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyRank),

		Params: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: poly.NewEvaluator[T](params.polyRank),

		PublicKey: pk,

		buf: newPublicEncryptorBuffer(params),
	}
}

// newPublicEncryptorBuffer creates a new publicEncryptorBuffer.
func newPublicEncryptorBuffer[T TorusInt](params Parameters[T]) publicEncryptorBuffer[T] {
	return publicEncryptorBuffer[T]{
		ptGLWE: NewGLWEPlaintext(params),
		ctGLWE: NewGLWECiphertext(params),

		auxKey:        NewGLWESecretKey(params),
		auxFourierKey: NewFFTGLWESecretKey(params),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *PublicEncryptor[T]) SafeCopy() *PublicEncryptor[T] {
	return &PublicEncryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.SafeCopy(),

		Params: e.Params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: e.PolyEvaluator.SafeCopy(),

		PublicKey: e.PublicKey,

		buf: newPublicEncryptorBuffer(e.Params),
	}
}
