package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// Encryptor is a multi-key variant of [tfhe.PublicEncryptor].
type PublicEncryptor[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this PublicEncryptor.
	*tfhe.Encoder[T]
	// GLWETansformer is an embedded GLWETransformer for this PublicEncryptor.
	*GLWETransformer[T]
	// SubEncryptor is a single-key PublicEncryptor for this PublicEncryptor.
	SubEncryptor *tfhe.PublicEncryptor[T]

	// Params is the parameters for this PublicEncryptor.
	Params Parameters[T]
	// Index is the index of the party.
	Index int

	// PublicKey is the public key for this PublicEncryptor.
	// This is shared with SingleKeyPublicEncryptor.
	PublicKey tfhe.PublicKey[T]

	buf publicEncryptorBuffer[T]
}

// publicEncryptorBuffer is a buffer for public encryption.
type publicEncryptorBuffer[T tfhe.TorusInt] struct {
	// ptGLWE is the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE is the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// ctSubLWE is the single-key LWE ciphertext.
	ctSubLWE tfhe.LWECiphertext[T]
	// ctSubGLWE is the single-key GLWE ciphertext.
	ctSubGLWE tfhe.GLWECiphertext[T]
}

// NewPublicEncryptor creates a new PublicEncryptor.
func NewPublicEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, publicKey tfhe.PublicKey[T]) *PublicEncryptor[T] {
	if idx > params.partyCount {
		panic("index larger than PartyCount")
	}

	return &PublicEncryptor[T]{
		Encoder:         tfhe.NewEncoder(params.subParams),
		GLWETransformer: NewGLWETransformer[T](params.PolyRank()),
		SubEncryptor:    tfhe.NewPublicEncryptor(params.subParams, publicKey),

		Params: params,
		Index:  idx,

		PublicKey: publicKey,

		buf: newPublicEncryptorBuffer(params),
	}
}

// newPublicEncryptorBuffer creates a new publicEncryptorBuffer.
func newPublicEncryptorBuffer[T tfhe.TorusInt](params Parameters[T]) publicEncryptorBuffer[T] {
	return publicEncryptorBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.subParams),
		ctGLWE: NewGLWECiphertext(params),

		ctSubLWE:  tfhe.NewLWECiphertext(params.subParams),
		ctSubGLWE: tfhe.NewGLWECiphertext(params.subParams),
	}
}

// ShallowCopy returns a shallow copy of the PublicEncryptor.
// Returned PublicEncryptor is safe for concurrent use.
func (e *PublicEncryptor[T]) ShallowCopy() *PublicEncryptor[T] {
	return &PublicEncryptor[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),
		SubEncryptor:    e.SubEncryptor.ShallowCopy(),

		Params: e.Params,
		Index:  e.Index,

		PublicKey: e.PublicKey,

		buf: newPublicEncryptorBuffer(e.Params),
	}
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWETo encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWETo(ctOut LWECiphertext[T], message int) {
	e.EncryptLWEPlaintextTo(ctOut, e.EncodeLWE(message))
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWEPlaintext(pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.EncryptLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptLWEPlaintextTo encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEPlaintextTo(ctOut LWECiphertext[T], pt tfhe.LWEPlaintext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
func (e *PublicEncryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.buf.ctSubLWE.Value[0] = ct.Value[0]
	e.SubEncryptor.EncryptLWEBody(e.buf.ctSubLWE)

	ct.Clear()
	ct.CopyFromSingleKey(e.buf.ctSubLWE, e.Index)
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWETo(ctOut, messages)
	return ctOut
}

// EncryptGLWETo encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWETo(ctOut GLWECiphertext[T], messages []int) {
	e.EncryptGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptGLWEPlaintextTo encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintextTo(ctOut GLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	e.buf.ctSubGLWE.Value[0].CopyFrom(ct.Value[0])
	e.SubEncryptor.EncryptGLWEBody(e.buf.ctSubGLWE)

	ct.Clear()
	ct.CopyFromSubKey(e.buf.ctSubGLWE, e.Index)
}

// EncryptFFTGLWE encodes and encrypts integer messages to FFTGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFFTGLWE(messages []int) FFTGLWECiphertext[T] {
	return e.EncryptFFTGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFFTGLWETo encrypts and encrypts integer messages to FFTGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFFTGLWETo(ctOut FFTGLWECiphertext[T], messages []int) {
	e.EncryptFFTGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptFFTGLWEPlaintext encrypts GLWE plaintext to FFTGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFFTGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.EncryptFFTGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptFFTGLWEPlaintextTo encrypts GLWE plaintext to FFTGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFFTGLWEPlaintextTo(ctOut FFTGLWECiphertext[T], pt tfhe.GLWEPlaintext[T]) {
	e.EncryptGLWEPlaintextTo(e.buf.ctGLWE, pt)
	e.ToFFTGLWECiphertextTo(ctOut, e.buf.ctGLWE)
}
