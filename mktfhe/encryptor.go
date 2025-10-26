package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Encryptor is a multi-key variant of [tfhe.Encryptor].
type Encryptor[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this Encryptor.
	*tfhe.Encoder[T]
	// GLWETansformer is an embedded GLWETransformer for this Encryptor.
	*GLWETransformer[T]
	// SubEncryptor is a single-key SubEncryptor for this SubEncryptor.
	SubEncryptor *tfhe.Encryptor[T]

	// Params is the parameters for this Encryptor.
	Params Parameters[T]
	// Index is the index of the party.
	Index int

	// CRS is the common reference string for this Encryptor.
	CRS []poly.Poly[T]

	// SecretKey is the secret key for this Encryptor.
	// This is shared with SingleKeyEncryptor.
	SecretKey tfhe.SecretKey[T]

	buf encryptorBuffer[T]
}

// encryptorBuffer is a buffer for encryption.
type encryptorBuffer[T tfhe.TorusInt] struct {
	// ptGLWE is the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE is the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// auxKey is the auxiliary key for uniencryption.
	auxKey tfhe.GLWESecretKey[T]
	// auxFourierKey is the fourier transform of auxKey.
	auxFourierKey tfhe.FFTGLWESecretKey[T]

	// ctSubLWE is the single-key LWE ciphertext.
	ctSubLWE tfhe.LWECiphertext[T]
	// ctSubGLWE is the single-key GLWE ciphertext.
	ctSubGLWE tfhe.GLWECiphertext[T]
}

// NewEncryptor creates a new Encryptor.
func NewEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte) *Encryptor[T] {
	if idx > params.partyCount {
		panic("NewEncryptor: index larger than PartyCount")
	}

	s := csprng.NewUniformSamplerWithSeed[T](crsSeed)
	crs := make([]poly.Poly[T], params.relinKeyParams.Level())
	for i := 0; i < params.relinKeyParams.Level(); i++ {
		crs[i] = poly.NewPoly[T](params.PolyRank())
		s.SamplePolyTo(crs[i])
	}

	enc := tfhe.NewEncryptor(params.subParams)

	return &Encryptor[T]{
		Encoder:         tfhe.NewEncoder(params.subParams),
		GLWETransformer: NewGLWETransformer[T](params.PolyRank()),
		SubEncryptor:    enc,

		Params: params,
		Index:  idx,

		CRS: crs,

		SecretKey: enc.SecretKey,

		buf: newEncryptorBuffer(params),
	}
}

// NewEncryptorWithKey creates a new Encryptor with a given key.
//
// Panics if the index is larger than PartyCount.
func NewEncryptorWithKey[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte, sk tfhe.SecretKey[T]) *Encryptor[T] {
	if idx > params.partyCount {
		panic("NewEncryptorWithKey: index larger than PartyCount")
	}

	s := csprng.NewUniformSamplerWithSeed[T](crsSeed)
	crs := make([]poly.Poly[T], params.relinKeyParams.Level())
	for i := 0; i < params.relinKeyParams.Level(); i++ {
		crs[i] = poly.NewPoly[T](params.PolyRank())
		s.SamplePolyTo(crs[i])
	}

	return &Encryptor[T]{
		Encoder:         tfhe.NewEncoder(params.subParams),
		GLWETransformer: NewGLWETransformer[T](params.PolyRank()),
		SubEncryptor:    tfhe.NewEncryptorWithKey(params.subParams, sk),

		Params: params,
		Index:  idx,

		CRS: crs,

		SecretKey: sk,

		buf: newEncryptorBuffer(params),
	}
}

// newEncryptorBuffer creates a new encryptorBuffer.
func newEncryptorBuffer[T tfhe.TorusInt](params Parameters[T]) encryptorBuffer[T] {
	return encryptorBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.subParams),
		ctGLWE: NewGLWECiphertext(params),

		auxKey:        tfhe.NewGLWESecretKey(params.subParams),
		auxFourierKey: tfhe.NewFFTGLWESecretKey(params.subParams),

		ctSubLWE:  tfhe.NewLWECiphertext(params.subParams),
		ctSubGLWE: tfhe.NewGLWECiphertext(params.subParams),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *Encryptor[T]) SafeCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.SafeCopy(),
		SubEncryptor:    e.SubEncryptor.SafeCopy(),

		Params: e.Params,
		Index:  e.Index,

		CRS: e.CRS,

		SecretKey: e.SecretKey,

		buf: newEncryptorBuffer(e.Params),
	}
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWETo encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWETo(ctOut LWECiphertext[T], message int) {
	e.EncryptLWEPlaintextTo(ctOut, e.EncodeLWE(message))
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWEPlaintext(pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.EncryptLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptLWEPlaintextTo encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEPlaintextTo(ctOut LWECiphertext[T], pt tfhe.LWEPlaintext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
func (e *Encryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.buf.ctSubLWE.Value[0] = ct.Value[0]
	e.SubEncryptor.EncryptLWEBody(e.buf.ctSubLWE)

	ct.Clear()
	ct.CopyFromSubKey(e.buf.ctSubLWE, e.Index)
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWETo(ctOut, messages)
	return ctOut
}

// EncryptGLWETo encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWETo(ctOut GLWECiphertext[T], messages []int) {
	e.EncryptGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptGLWEPlaintextTo encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEPlaintextTo(ctOut GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	e.buf.ctSubGLWE.Value[0].CopyFrom(ct.Value[0])
	e.SubEncryptor.EncryptGLWEBody(e.buf.ctSubGLWE)

	ct.Clear()
	ct.CopyFromSubKey(e.buf.ctSubGLWE, e.Index)
}

// EncryptFFTGLWE encodes and encrypts integer messages to FFTGLWE ciphertext.
func (e *Encryptor[T]) EncryptFFTGLWE(messages []int) FFTGLWECiphertext[T] {
	return e.EncryptFFTGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFFTGLWETo encrypts and encrypts integer messages to FFTGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLWETo(ctOut FFTGLWECiphertext[T], messages []int) {
	e.EncryptFFTGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptFFTGLWEPlaintext encrypts GLWE plaintext to FFTGLWE ciphertext.
func (e *Encryptor[T]) EncryptFFTGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.EncryptFFTGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptFFTGLWEPlaintextTo encrypts GLWE plaintext to FFTGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLWEPlaintextTo(ctOut FFTGLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	e.EncryptGLWEPlaintextTo(e.buf.ctGLWE, pt)
	e.ToFFTGLWECiphertextTo(ctOut, e.buf.ctGLWE)
}

// GenPublicKey samples a new PublicKey.
//
// Panics when the parameters do not support public key encryption.
func (e *Encryptor[T]) GenPublicKey() tfhe.PublicKey[T] {
	return e.SubEncryptor.GenPublicKey()
}
