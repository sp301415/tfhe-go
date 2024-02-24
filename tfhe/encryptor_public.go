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
// Use [*PublicEncryptor.ShallowCopy] to get a safe copy.
type PublicEncryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this PublicEncryptor.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Encryptor.
	*GLWETransformer[T]

	// Parameters holds the parameters for this PublicEncryptor.
	Parameters Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler csprng.UniformSampler[T]
	// BinarySampler is used for sampling the auxillary "key" in encryptions.
	BinarySampler csprng.BinarySampler[T]
	// GaussianSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler csprng.GaussianSampler[T]

	// PolyEvaluator holds the PolyEvaluator for this PublicEncryptor.
	PolyEvaluator *poly.Evaluator[T]
	// FourierEvaluator holds the FourierEvaluator for this PublicEncryptor.
	FourierEvaluator *poly.FourierEvaluator[T]

	// PublicKey holds the public key for this PublicEncryptor.
	PublicKey PublicKey[T]

	// buffer holds the buffer values for this PublicEncryptor.
	buffer publicEncryptionBuffer[T]
}

// publicEncryptionBuffer contains buffer values for PublicEncryptor.
type publicEncryptionBuffer[T TorusInt] struct {
	// ptGLWE holds the GLWE plaintext for GLWE encryption / decryptions.
	ptGLWE GLWEPlaintext[T]
	// ctGLWE holds standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]

	// auxKey holds the auxillary key for encryption.
	// This must be sampled fresh for each encryption.
	auxKey GLWESecretKey[T]
	// auxFourierKey holds the fourier transform of auxKey.
	auxFourierKey FourierGLWESecretKey[T]
}

// NewPublicEncryptor allocates a new PublicEncryptor.
//
// Panics when the parameters do not support public key encryption.
func NewPublicEncryptor[T TorusInt](params Parameters[T], pk PublicKey[T]) *PublicEncryptor[T] {
	if !params.IsPublicKeyEncryptable() {
		panic("Parameters do not support public key encryption")
	}

	return &PublicEncryptor[T]{
		Encoder:         NewEncoder[T](params),
		GLWETransformer: NewGLWETransformer(params),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		PublicKey: pk,

		buffer: newPublicEncryptionBuffer(params),
	}
}

// newPublicEncryptionBuffer allocates a new publicEncryptionBuffer.
func newPublicEncryptionBuffer[T TorusInt](params Parameters[T]) publicEncryptionBuffer[T] {
	return publicEncryptionBuffer[T]{
		ptGLWE: NewGLWEPlaintext[T](params),
		ctGLWE: NewGLWECiphertext[T](params),

		auxKey:        NewGLWESecretKey[T](params),
		auxFourierKey: NewFourierGLWESecretKey[T](params),
	}
}

// ShallowCopy returns a shallow copy of the PublicEncryptor.
func (e *PublicEncryptor[T]) ShallowCopy() *PublicEncryptor[T] {
	return &PublicEncryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		Parameters: e.Parameters,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator:    e.PolyEvaluator.ShallowCopy(),
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),

		PublicKey: e.PublicKey,

		buffer: newPublicEncryptionBuffer(e.Parameters),
	}
}
