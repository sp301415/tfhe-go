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
	// SingleKeyPublicEncryptor is a single-key PublicEncryptor for this PublicEncryptor.
	SingleKeyPublicEncryptor *tfhe.PublicEncryptor[T]

	// Parameters is the parameters for this PublicEncryptor.
	Parameters Parameters[T]
	// Index is the index of the party.
	Index int

	// PublicKey is the public key for this PublicEncryptor.
	// This is shared with SingleKeyPublicEncryptor.
	PublicKey tfhe.PublicKey[T]

	// buffer is a buffer for this PublicEncryptor.
	buffer publicEncryptionBuffer[T]
}

// publicEncryptionBuffer is a buffer for public encryption.
type publicEncryptionBuffer[T tfhe.TorusInt] struct {
	// ptGLWE holds the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE holds the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// ctLWESingle holds the single-key LWE ciphertext.
	ctLWESingle tfhe.LWECiphertext[T]
	// ctGLWESingle holds the single-key GLWE ciphertext.
	ctGLWESingle tfhe.GLWECiphertext[T]
}

// NewPublicEncryptor allocates an empty PublicEncryptor.
func NewPublicEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, publicKey tfhe.PublicKey[T]) *PublicEncryptor[T] {
	if idx > params.partyCount {
		panic("index larger than PartyCount")
	}

	return &PublicEncryptor[T]{
		Encoder:                  tfhe.NewEncoder[T](params.Parameters),
		GLWETransformer:          NewGLWETransformer(params),
		SingleKeyPublicEncryptor: tfhe.NewPublicEncryptor(params.Parameters, publicKey),

		Parameters: params,
		Index:      idx,

		PublicKey: publicKey,

		buffer: newPublicEncryptionBuffer(params),
	}
}

// newPublicEncryptionBuffer allocates a new publicEncryptionBuffer.
func newPublicEncryptionBuffer[T tfhe.TorusInt](params Parameters[T]) publicEncryptionBuffer[T] {
	return publicEncryptionBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.Parameters),
		ctGLWE: NewGLWECiphertext(params),

		ctLWESingle:  tfhe.NewLWECiphertext(params.Parameters),
		ctGLWESingle: tfhe.NewGLWECiphertext(params.Parameters),
	}
}

// ShallowCopy returns a shallow copy of the PublicEncryptor.
// Returned PublicEncryptor is safe for concurrent use.
func (e *PublicEncryptor[T]) ShallowCopy() *PublicEncryptor[T] {
	return &PublicEncryptor[T]{
		Encoder:                  e.Encoder,
		GLWETransformer:          e.GLWETransformer.ShallowCopy(),
		SingleKeyPublicEncryptor: e.SingleKeyPublicEncryptor.ShallowCopy(),

		Parameters: e.Parameters,
		Index:      e.Index,

		PublicKey: e.PublicKey,

		buffer: newPublicEncryptionBuffer(e.Parameters),
	}
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEAssign encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEAssign(message int, ctOut LWECiphertext[T]) {
	e.EncryptLWEPlaintextAssign(e.EncodeLWE(message), ctOut)
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWEPlaintext(pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptLWEPlaintextAssign encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEPlaintextAssign(pt tfhe.LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
func (e *PublicEncryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.buffer.ctLWESingle.Value[0] = ct.Value[0]
	e.SingleKeyPublicEncryptor.EncryptLWEBody(e.buffer.ctLWESingle)

	ct.Clear()
	ct.CopyFromSingleKey(e.buffer.ctLWESingle, e.Index)
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEAssign(messages, ctOut)
	return ctOut
}

// EncryptGLWEAssign encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEAssign(messages []int, ctOut GLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	e.buffer.ctGLWESingle.Value[0].CopyFrom(ct.Value[0])
	e.SingleKeyPublicEncryptor.EncryptGLWEBody(e.buffer.ctGLWESingle)

	ct.Clear()
	ct.CopyFromSingleKey(e.buffer.ctGLWESingle, e.Index)
}

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEAssign encrypts and encrypts integer messages to FourierGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLWEAssign(messages []int, ctOut FourierGLWECiphertext[T]) {
	e.EncryptFourierGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ct := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLWEPlaintextAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLWEPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}
