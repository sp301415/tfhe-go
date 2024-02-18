package tfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// PublicEncryptor encrypts TFHE ciphertexts with public key.
// This is meant to be public, usually for servers.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
// Namely, DefaultLWEDimension should be power of two.
//
// PublicEncryptor is not safe for concurrent use.
// Use [*PublicEncryptor.ShallowCopy] to get a safe copy.
type PublicEncryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this PublicEncryptor.
	*Encoder[T]
	// glweTransformer is an embedded glweTransformer for this PublicEncryptor.
	*glweTransformer[T]

	// Parameters holds the parameters for this PublicEncryptor.
	Parameters Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler csprng.UniformSampler[T]
	// BinarySampler is used for sampling the auxillary "key" in encryptions.
	BinarySampler csprng.BinarySampler[T]
	// GaussianSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler csprng.GaussianSampler[T]

	// LWEPolyEvaluator holds the PolyEvaluator for LWE encryption.
	LWEPolyEvaluator *poly.Evaluator[T]
	// LWEFourierEvaluator holds the FourierEvaluator for LWE encryption.
	LWEFourierEvaluator *poly.FourierEvaluator[T]
	// GLWEPolyEvaluator holds the PolyEvaluator for GLWE encryption.
	GLWEPolyEvaluator *poly.Evaluator[T]
	// GLWEFourierEvaluator holds the FourierEvaluator for GLWE encryption.
	GLWEFourierEvaluator *poly.FourierEvaluator[T]

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

	// auxLWEKey holds the auxillary key for LWE encryption.
	// This must be sampled fresh for each encryption.
	auxLWEKey poly.Poly[T]
	// auxFourierLWEKey holds the fourier transform of auxLWEKey.
	auxFourierLWEKey poly.FourierPoly

	// auxGLWEKey holds the auxillary key for GLWE encryption.
	// This must be sampled fresh for each encryption.
	auxGLWEKey GLWESecretKey[T]
	// auxFourierGLWEKey holds the fourier transform of auxGLWEKey.
	auxFourierGLWEKey FourierGLWESecretKey[T]

	// pLWESplit is a buffer for split polynomial in mulLWEKey.
	pLWESplit poly.Poly[T]
	// fpLWESplit is a buffer for split fourier polynomial in mulLWEKey.
	fpLWESplit poly.FourierPoly

	// pGLWESplit is a buffer for split polynomial in mulGLWEKey.
	pGLWESplit poly.Poly[T]
	// fpGLWESplit is a buffer for split fourier polynomial in mulGLWEKey.
	fpGLWESplit poly.FourierPoly
}

// NewPublicEncryptor creates a new PublicEncryptor with the given parameters and PublicKey.
func NewPublicEncryptor[T TorusInt](params Parameters[T], pk PublicKey[T]) *PublicEncryptor[T] {
	if !num.IsPowerOfTwo(params.DefaultLWEDimension()) {
		panic("Default LWE dimension not a power of two")
	}

	return &PublicEncryptor[T]{
		Encoder:         NewEncoder(params),
		glweTransformer: newGLWETransformer[T](params),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		LWEPolyEvaluator:     poly.NewEvaluator[T](params.DefaultLWEDimension()),
		LWEFourierEvaluator:  poly.NewFourierEvaluator[T](params.DefaultLWEDimension()),
		GLWEPolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		GLWEFourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		PublicKey: pk,

		buffer: newPublicEncryptionBuffer[T](params),
	}
}

// newPublicEncryptionBuffer returns a new publicEncryptionBuffer.
func newPublicEncryptionBuffer[T TorusInt](params Parameters[T]) publicEncryptionBuffer[T] {
	return publicEncryptionBuffer[T]{
		ptGLWE: NewGLWEPlaintext(params),
		ctGLWE: NewGLWECiphertext(params),

		auxLWEKey:        poly.NewPoly[T](params.DefaultLWEDimension()),
		auxFourierLWEKey: poly.NewFourierPoly(params.DefaultLWEDimension()),

		auxGLWEKey:        NewGLWESecretKey(params),
		auxFourierGLWEKey: NewFourierGLWESecretKey(params),

		pLWESplit:  poly.NewPoly[T](params.DefaultLWEDimension()),
		fpLWESplit: poly.NewFourierPoly(params.DefaultLWEDimension()),

		pGLWESplit:  poly.NewPoly[T](params.polyDegree),
		fpGLWESplit: poly.NewFourierPoly(params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this PublicEncryptor.
func (e *PublicEncryptor[T]) ShallowCopy() *PublicEncryptor[T] {
	return &PublicEncryptor[T]{
		Encoder:         e.Encoder,
		glweTransformer: e.glweTransformer.ShallowCopy(),

		Parameters: e.Parameters,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		LWEPolyEvaluator:     e.LWEPolyEvaluator.ShallowCopy(),
		LWEFourierEvaluator:  e.LWEFourierEvaluator.ShallowCopy(),
		GLWEPolyEvaluator:    e.GLWEPolyEvaluator.ShallowCopy(),
		GLWEFourierEvaluator: e.GLWEFourierEvaluator.ShallowCopy(),

		PublicKey: e.PublicKey,

		buffer: newPublicEncryptionBuffer(e.Parameters),
	}
}
