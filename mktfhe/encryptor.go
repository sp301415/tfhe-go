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
	// SingleKeyEncryptor is a single-key Encryptor for this Encryptor.
	SingleKeyEncryptor *tfhe.Encryptor[T]

	// Parameters is the parameters for the encryptor.
	Parameters Parameters[T]
	// Index is the index of the party.
	Index int

	// CRS is the common reference string for this Encryptor.
	CRS []poly.Poly[T]

	// SecretKey is the secret key for this Encryptor.
	// This is shared with SingleKeyEncryptor.
	SecretKey tfhe.SecretKey[T]

	// buffer is a buffer for this Encryptor.
	buffer encryptionBuffer[T]
}

// encryptionBuffer is a buffer for encryption.
type encryptionBuffer[T tfhe.TorusInt] struct {
	// ptGLWE holds the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE holds the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// auxKey holds the auxiliary key for uniencryption.
	auxKey tfhe.GLWESecretKey[T]
	// auxFourierKey holds the fourier transform of auxKey.
	auxFourierKey tfhe.FourierGLWESecretKey[T]

	// ctLWESingle holds the single-key LWE ciphertext.
	ctLWESingle tfhe.LWECiphertext[T]
	// ctGLWESingle holds the single-key GLWE ciphertext.
	ctGLWESingle tfhe.GLWECiphertext[T]
}

// NewEncryptor allocates an empty Encryptor.
func NewEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte) *Encryptor[T] {
	if idx > params.partyCount {
		panic("index larger than PartyCount")
	}

	s := csprng.NewUniformSamplerWithSeed[T](crsSeed)
	crs := make([]poly.Poly[T], params.relinKeyParameters.Level())
	for i := 0; i < params.relinKeyParameters.Level(); i++ {
		crs[i] = poly.NewPoly[T](params.PolyDegree())
		s.SampleSliceAssign(crs[i].Coeffs)
	}

	enc := tfhe.NewEncryptor(params.Parameters)

	return &Encryptor[T]{
		Encoder:            tfhe.NewEncoder(params.Parameters),
		GLWETransformer:    NewGLWETransformer(params),
		SingleKeyEncryptor: enc,

		Parameters: params,
		Index:      idx,

		CRS: crs,

		SecretKey: enc.SecretKey,

		buffer: newEncryptionBuffer(params),
	}
}

// NewEncryptorWithKey allocates an empty Encryptor with a given key.
//
// Panics if the index is larger than PartyCount.
func NewEncryptorWithKey[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte, sk tfhe.SecretKey[T]) *Encryptor[T] {
	if idx > params.partyCount {
		panic("index larger than PartyCount")
	}

	s := csprng.NewUniformSamplerWithSeed[T](crsSeed)
	crs := make([]poly.Poly[T], params.relinKeyParameters.Level())
	for i := 0; i < params.relinKeyParameters.Level(); i++ {
		crs[i] = poly.NewPoly[T](params.PolyDegree())
		s.SampleSliceAssign(crs[i].Coeffs)
	}

	return &Encryptor[T]{
		Encoder:            tfhe.NewEncoder(params.Parameters),
		GLWETransformer:    NewGLWETransformer(params),
		SingleKeyEncryptor: tfhe.NewEncryptorWithKey(params.Parameters, sk),

		Parameters: params,
		Index:      idx,

		CRS: crs,

		SecretKey: sk,

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T tfhe.TorusInt](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.Parameters),
		ctGLWE: NewGLWECiphertext(params),

		auxKey:        tfhe.NewGLWESecretKey(params.Parameters),
		auxFourierKey: tfhe.NewFourierGLWESecretKey(params.Parameters),

		ctLWESingle:  tfhe.NewLWECiphertext(params.Parameters),
		ctGLWESingle: tfhe.NewGLWECiphertext(params.Parameters),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor[T]) ShallowCopy() *Encryptor[T] {
	return &Encryptor[T]{
		Encoder:            e.Encoder,
		GLWETransformer:    e.GLWETransformer.ShallowCopy(),
		SingleKeyEncryptor: e.SingleKeyEncryptor.ShallowCopy(),

		Parameters: e.Parameters,
		Index:      e.Index,

		CRS: e.CRS,

		SecretKey: e.SecretKey,

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
	e.SingleKeyEncryptor.EncryptLWEBody(e.buffer.ctLWESingle)

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
	e.SingleKeyEncryptor.EncryptGLWEBody(e.buffer.ctGLWESingle)

	ct.Clear()
	ct.CopyFromSingleKey(e.buffer.ctGLWESingle, e.Index)
}

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *Encryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEAssign encrypts and encrypts integer messages to FourierGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLWEAssign(messages []int, ctOut FourierGLWECiphertext[T]) {
	e.EncryptFourierGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e *Encryptor[T]) EncryptFourierGLWEPlaintext(pt tfhe.GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ct := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLWEPlaintextAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLWEPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}
