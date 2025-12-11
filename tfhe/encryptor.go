package tfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// Encryptor encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
//
// Encryptor is not safe for concurrent use.
// Use [*Encryptor.SafeCopy] to get a safe copy.
type Encryptor[T TorusInt] struct {
	// Encoder is an embedded encoder for this Encryptor.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Encryptor.
	*GLWETransformer[T]

	// Params is parameters for this Encryptor.
	Params Parameters[T]

	// UniformSampler is used for sampling the mask of encryptions.
	UniformSampler *csprng.UniformSampler[T]
	// BinarySampler is used for sampling LWE and GLWE key.
	BinarySampler *csprng.BinarySampler[T]
	// GaussianSampler is used for sampling noise in LWE and GLWE encryption.
	GaussianSampler *csprng.GaussianSampler[T]

	// PolyEvaluator is a PolyEvaluator for this Encryptor.
	PolyEvaluator *poly.Evaluator[T]

	// SecretKey is the LWE and GLWE key for this Encryptor.
	//
	// The LWE key used for LWE ciphertexts is determined by
	// BootstrapOrder.
	// For encrypting/decrypting LWE ciphertexts, use [*Encryptor DefaultLWEKey].
	SecretKey SecretKey[T]

	buf encryptorBuffer[T]
}

// encryptorBuffer is a buffer for Encryptor.
type encryptorBuffer[T TorusInt] struct {
	// ptGLWE is a GLWE plaintext for GLWE encryption / decryptions.
	ptGLWE GLWEPlaintext[T]
	// ctGLWE is a standard GLWE Ciphertext for Fourier encryption / decryptions.
	ctGLWE GLWECiphertext[T]
	// ptGGSW is GLWEKey * Pt in GGSW encryption.
	ptGGSW poly.Poly[T]
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor[T TorusInt](params Parameters[T]) *Encryptor[T] {
	// Fill samplers to call encryptor.GenSecretKey()
	encryptor := Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyRank),

		Params: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: poly.NewEvaluator[T](params.polyRank),

		buf: newEncryptorBuffer(params),
	}

	encryptor.SecretKey = encryptor.GenSecretKey()

	return &encryptor
}

// NewEncryptorWithKey returns a initialized Encryptor with given parameters and key.
// This does not copy secret keys.
func NewEncryptorWithKey[T TorusInt](params Parameters[T], sk SecretKey[T]) *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyRank),

		Params: params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		PolyEvaluator: poly.NewEvaluator[T](params.polyRank),

		SecretKey: sk,

		buf: newEncryptorBuffer(params),
	}
}

// newEncryptorBuffer creates a new encryptorBuffer.
func newEncryptorBuffer[T TorusInt](params Parameters[T]) encryptorBuffer[T] {
	return encryptorBuffer[T]{
		ptGLWE: NewGLWEPlaintext(params),
		ctGLWE: NewGLWECiphertext(params),
		ptGGSW: poly.NewPoly[T](params.polyRank),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *Encryptor[T]) SafeCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.SafeCopy(),

		Params: e.Params,

		UniformSampler:  csprng.NewUniformSampler[T](),
		BinarySampler:   csprng.NewBinarySampler[T](),
		GaussianSampler: csprng.NewGaussianSampler[T](),

		SecretKey: e.SecretKey,

		PolyEvaluator: e.PolyEvaluator.SafeCopy(),

		buf: newEncryptorBuffer(e.Params),
	}
}

// DefaultLWESecretKey returns the LWE key according to the parameters.
// Returns LWELargeKey if BootstrapOrder is OrderKeySwitchBlindRotate,
// or LWEKey otherwise.
func (e *Encryptor[T]) DefaultLWESecretKey() LWESecretKey[T] {
	if e.Params.bootstrapOrder == OrderKeySwitchBlindRotate {
		return e.SecretKey.LWELargeKey
	}
	return e.SecretKey.LWEKey
}

// GenSecretKey samples a new SecretKey.
// The SecretKey of the Encryptor is not changed.
func (e *Encryptor[T]) GenSecretKey() SecretKey[T] {
	sk := NewSecretKey(e.Params)

	if e.Params.blockSize == 1 {
		e.BinarySampler.SampleVecTo(sk.LWELargeKey.Value)
	} else {
		e.BinarySampler.SampleBlockVecTo(sk.LWELargeKey.Value[:e.Params.lweDimension], e.Params.blockSize)
		e.BinarySampler.SampleVecTo(sk.LWELargeKey.Value[e.Params.lweDimension:])
	}

	e.FwdFFTGLWESecretKeyTo(sk.FFTGLWEKey, sk.GLWEKey)

	return sk
}

// GenPublicKey samples a new PublicKey.
//
// Panics when the parameters do not support public key encryption.
func (e *Encryptor[T]) GenPublicKey() PublicKey[T] {
	if !e.Params.IsPublicKeyEncryptable() {
		panic("Parameters do not support public key encryption")
	}

	pk := NewPublicKey(e.Params)

	for i := 0; i < e.Params.glweRank; i++ {
		e.EncryptGLWEBody(pk.GLWEKey.Value[i])
	}

	skRev := NewGLWESecretKey(e.Params)
	fskRev := NewFFTGLWESecretKey(e.Params)
	for i := 0; i < e.Params.glweRank; i++ {
		vec.ReverseTo(skRev.Value[i].Coeffs, e.SecretKey.GLWEKey.Value[i].Coeffs)
	}
	e.FwdFFTGLWESecretKeyTo(fskRev, skRev)

	for i := 0; i < e.Params.glweRank; i++ {
		e.GaussianSampler.SamplePolyTo(pk.LWEKey.Value[i].Value[0], e.Params.GLWEStdDevQ())
		for j := 1; j < e.Params.glweRank+1; j++ {
			e.UniformSampler.SamplePolyTo(pk.LWEKey.Value[i].Value[j])
			e.PolyEvaluator.ShortFFTPolyMulSubPolyTo(pk.LWEKey.Value[i].Value[0], pk.LWEKey.Value[i].Value[j], fskRev.Value[j-1])
		}
	}

	return pk
}
