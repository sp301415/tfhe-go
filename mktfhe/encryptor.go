package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// Encryptor is a Multi-Key variant of [tfhe.Encryptor].
type Encryptor[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this Encryptor.
	*tfhe.Encoder[T]
	// Encryptor is a single-key Encryptor for this Encryptor.
	*tfhe.Encryptor[T]

	// Parameters is the parameters for the encryptor.
	Parameters Parameters[T]
	// Index is the index of the party.
	Index int

	// buffer is a buffer for this Encryptor.
	buffer encryptionBuffer[T]
}

// encryptionBuffer is a buffer for encryption.
type encryptionBuffer[T tfhe.TorusInt] struct {
	// ctLWESingle holds the single-key LWE ciphertext.
	ctLWESingle tfhe.LWECiphertext[T]

	// ctGLWESingle holds the single-key GLWE ciphertext.
	ctGLWESingle tfhe.GLWECiphertext[T]
}

// NewEncryptor creates a new Encryptor.
func NewEncryptor[T tfhe.TorusInt](params Parameters[T], idx int) *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:   tfhe.NewEncoder(params.Parameters),
		Encryptor: tfhe.NewEncryptor(params.Parameters),

		Parameters: params,
		Index:      idx,

		buffer: newEncryptionBuffer(params),
	}
}

// NewEncryptorWithKey creates a new Encryptor with a given key.
func NewEncryptorWithKey[T tfhe.TorusInt](params Parameters[T], idx int, sk tfhe.SecretKey[T]) *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:   tfhe.NewEncoder(params.Parameters),
		Encryptor: tfhe.NewEncryptorWithKey(params.Parameters, sk),

		Parameters: params,
		Index:      idx,

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer creates a new encryptionBuffer.
func newEncryptionBuffer[T tfhe.TorusInt](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ctLWESingle:  tfhe.NewLWECiphertext(params.Parameters),
		ctGLWESingle: tfhe.NewGLWECiphertext(params.Parameters),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor[T]) ShallowCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:   e.Encoder,
		Encryptor: e.Encryptor.ShallowCopy(),

		Parameters: e.Parameters,
		Index:      e.Index,

		buffer: newEncryptionBuffer(e.Parameters),
	}
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEAssign encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEAssign(message int, ctOut LWECiphertext[T]) {
	e.EncryptLWEPlaintextAssign(e.EncodeLWE(message), ctOut)
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWEPlaintext(pt tfhe.LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptLWEPlaintextAssign encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEPlaintextAssign(pt tfhe.LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
func (e *Encryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.buffer.ctLWESingle.Value[0] = ct.Value[0]
	e.Encryptor.EncryptLWEBody(e.buffer.ctLWESingle)

	ct.Clear()
	ct.CopyFromSingleKey(e.buffer.ctLWESingle, e.Index)
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEAssign(messages, ctOut)
	return ctOut
}

// EncryptGLWEAssign encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEAssign(messages []int, ctOut GLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	e.buffer.ctGLWESingle.Value[0].CopyFrom(ct.Value[0])
	e.Encryptor.EncryptGLWEBody(e.buffer.ctGLWESingle)

	ct.Clear()
	ct.CopyFromSingleKey(e.buffer.ctGLWESingle, e.Index)
}
