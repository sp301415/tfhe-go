package tfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Encryptor encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
type Encryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this Encryptor.
	*Encoder[T]

	// Parameters holds the parameters for this Encryptor.
	Parameters Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler csprng.UniformSampler[T]
	// BinarySampler is used for sampling GLWE key.
	BinarySampler csprng.BinarySampler[T]
	// BlockSampler is used for sampling LWE key.
	BlockSampler csprng.BlockSampler[T]
	// LWESampler is used for sampling the error of LWE encryption.
	//
	// In case of LWE ciphertexts, the error distribution
	// is determinted by BootstrapOrder.
	// For sampling error for LWE ciphertexts, use DefaultLWESampler().
	LWESampler csprng.GaussianSampler[T]
	// GLWESampler is used for sampling the error of GLWE encryption.
	GLWESampler csprng.GaussianSampler[T]

	// PolyEvaluator holds the PolyEvaluator for this Encryptor.
	PolyEvaluator *poly.Evaluator[T]
	// FourierEvaluator holds the FourierEvaluator for this Encryptor.
	FourierEvaluator *poly.FourierEvaluator[T]

	// SecretKey holds the LWE and GLWE key for this Encryptor.
	//
	// The LWE key used for LWE ciphertexts is determined by
	// BootstrapOrder.
	// For encrypting/decrypting LWE ciphertexts, use DefaultLWEKey().
	SecretKey SecretKey[T]

	// buffer holds the buffer values for this Encryptor.
	buffer encryptionBuffer[T]
}

// encryptionBuffer contains buffer values for Encryptor.
type encryptionBuffer[T TorusInt] struct {
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
		Encoder: NewEncoder(params),

		Parameters: params,

		UniformSampler: csprng.NewUniformSampler[T](),
		BinarySampler:  csprng.NewBinarySampler[T](),
		BlockSampler:   csprng.NewBlockSampler[T](params.blockSize),
		LWESampler:     csprng.NewGaussianSamplerScaled[T](params.lweStdDev),
		GLWESampler:    csprng.NewGaussianSamplerScaled[T](params.glweStdDev),

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
		Encoder: NewEncoder(params),

		Parameters: params,

		UniformSampler: csprng.NewUniformSampler[T](),
		BinarySampler:  csprng.NewBinarySampler[T](),
		BlockSampler:   csprng.NewBlockSampler[T](params.blockSize),
		LWESampler:     csprng.NewGaussianSamplerScaled[T](params.lweStdDev),
		GLWESampler:    csprng.NewGaussianSamplerScaled[T](params.glweStdDev),

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		SecretKey: sk,

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T TorusInt](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ctGLWE:  NewGLWECiphertext(params),
		ptGGSW:  poly.NewPoly[T](params.polyDegree),
		pSplit:  poly.NewPoly[T](params.polyDegree),
		fpSplit: poly.NewFourierPoly(params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor[T]) ShallowCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder: e.Encoder,

		Parameters: e.Parameters,

		UniformSampler: csprng.NewUniformSampler[T](),
		BinarySampler:  csprng.NewBinarySampler[T](),
		LWESampler:     csprng.NewGaussianSamplerScaled[T](e.Parameters.lweStdDev),
		GLWESampler:    csprng.NewGaussianSamplerScaled[T](e.Parameters.glweStdDev),

		SecretKey: e.SecretKey,

		PolyEvaluator:    e.PolyEvaluator.ShallowCopy(),
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}

// GenSecretKey samples a new SecretKey.
func (e *Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Parameters)

	if e.Parameters.blockSize == 1 {
		e.BinarySampler.SampleSliceAssign(sk.LWELargeKey.Value)
	} else {
		e.BlockSampler.SampleSliceAssign(sk.LWELargeKey.Value[:e.Parameters.lweDimension])
		e.BinarySampler.SampleSliceAssign(sk.LWELargeKey.Value[e.Parameters.lweDimension:])
	}

	e.ToFourierGLWEKeyAssign(sk.GLWEKey, sk.FourierGLWEKey)

	return sk
}
