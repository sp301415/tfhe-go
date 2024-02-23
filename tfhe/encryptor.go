package tfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Encryptor encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
//
// Encrryptor is not safe for concurrent use.
// Use [*Encryptor.ShallowCopy] to get a safe copy.
type Encryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this Encryptor.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Encryptor.
	*GLWETransformer[T]

	// Parameters holds the parameters for this Encryptor.
	Parameters Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler csprng.UniformSampler[T]
	// BinarySampler is used for sampling LWE and GLWE key.
	BinarySampler csprng.BinarySampler[T]
	// GaussainSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler csprng.GaussianSampler[T]

	// PolyEvaluator holds the PolyEvaluator for this Encryptor.
	PolyEvaluator *poly.Evaluator[T]
	// FourierEvaluator holds the FourierEvaluator for this Encryptor.
	FourierEvaluator *poly.FourierEvaluator[T]

	// SecretKey holds the LWE and GLWE key for this Encryptor.
	//
	// The LWE key used for LWE ciphertexts is determined by
	// BootstrapOrder.
	// For encrypting/decrypting LWE ciphertexts, use [*Encryptor DefaultLWEKey].
	SecretKey SecretKey[T]

	// buffer holds the buffer values for this Encryptor.
	buffer encryptionBuffer[T]
}

// encryptionBuffer contains buffer values for Encryptor.
type encryptionBuffer[T TorusInt] struct {
	// ptGLWE holds the GLWE plaintext for GLWE encryption / decryptions.
	ptGLWE GLWEPlaintext[T]
	// ctGLWE holds standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]
	// ptGGSW holds GLWEKey * Pt in GGSW encryption.
	ptGGSW poly.Poly[T]

	// pSplit is a buffer for split polynomial in mulGLWEKey.
	pSplit poly.Poly[T]
	// fpSplit is a buffer for split fourier polynomial in mulGLWEKey.
	fpSplit poly.FourierPoly
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor[T TorusInt](params Parameters[T]) *Encryptor[T] {
	// Fill samplers to call encryptor.GenSecretKey()
	encryptor := Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: newGLWETransformer(params),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		buffer: newEncryptionBuffer(params),
	}

	encryptor.SecretKey = encryptor.GenSecretKey()

	return &encryptor
}

// NewEncryptorWithKey returns a initialized Encryptor with given parameters,
// with the supplied SecretKey.
// This does not copy the SecretKey.
func NewEncryptorWithKey[T TorusInt](params Parameters[T], sk SecretKey[T]) *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: newGLWETransformer(params),

		Parameters: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		SecretKey: sk,

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T TorusInt](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ptGLWE: NewGLWEPlaintext(params),
		ctGLWE: NewGLWECiphertext(params),
		ptGGSW: poly.NewPoly[T](params.polyDegree),

		pSplit:  poly.NewPoly[T](params.polyDegree),
		fpSplit: poly.NewFourierPoly(params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor[T]) ShallowCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		Parameters: e.Parameters,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		SecretKey: e.SecretKey,

		PolyEvaluator:    e.PolyEvaluator.ShallowCopy(),
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}

// GenSecretKey samples a new SecretKey.
// The SecretKey of the Encryptor is not changed.
func (e *Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Parameters)

	if e.Parameters.blockSize == 1 {
		e.BinarySampler.SampleSliceAssign(sk.LWELargeKey.Value)
	} else {
		e.BinarySampler.SampleBlockSliceAssign(e.Parameters.blockSize, sk.LWELargeKey.Value[:e.Parameters.lweDimension])
		e.BinarySampler.SampleSliceAssign(sk.LWELargeKey.Value[e.Parameters.lweDimension:])
	}

	e.ToFourierGLWESecretKeyAssign(sk.GLWEKey, sk.FourierGLWEKey)

	return sk
}

// DefaultLWESecretKey returns the LWE key according to the parameters.
// Returns LWELargeKey if BootstrapOrder is OrderKeySwitchBlindRotate,
// or LWEKey otherwise.
func (e *Encryptor[T]) DefaultLWESecretKey() LWESecretKey[T] {
	if e.Parameters.bootstrapOrder == OrderKeySwitchBlindRotate {
		return e.SecretKey.LWELargeKey
	}
	return e.SecretKey.LWEKey
}
