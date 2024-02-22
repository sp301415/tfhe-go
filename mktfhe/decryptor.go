package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Decryptor is a Multi-Key TFHE decryptor.
//
// Ideally, a multi-key ciphertext should be decrypted
// by a distributed decryption protocol.
// However, in TFHE, this procedure is very difficult and slow.
// Therefore, we provide a all-knowing decryptor for simplicity.
//
// Decryptor is not safe for concurrent use.
// Use [*Decryptor.ShallowCopy] to get a safe copy.
type Decryptor[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this Decryptor.
	*tfhe.Encoder[T]
	// BaseEncryptors are a single-key Encryptors for this Decryptor.
	BaseEncryptors []*tfhe.Encryptor[T]

	// Parameters is the parameters for the decryptor.
	Parameters Parameters[T]

	// buffer is a buffer for this Decryptor.
	buffer decryptionBuffer[T]
}

// decryptionBuffer is a buffer for decryption.
type decryptionBuffer[T tfhe.TorusInt] struct {
	// ctLWE holds the LWE ciphertext.
	ctLWE tfhe.LWECiphertext[T]
	// ctGLWE holds the GLWE ciphertext.
	ctGLWE tfhe.GLWECiphertext[T]
	// ptGLWE holds the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
}

// NewDecryptor creates a new Decryptor.
// Any number of secret keys less than or equal to PartyCount can be used.
func NewDecryptor[T tfhe.TorusInt](params Parameters[T], sk []tfhe.SecretKey[T]) *Decryptor[T] {
	if len(sk) > params.partyCount {
		panic("secret key length larger than PartyCount")
	}

	encs := make([]*tfhe.Encryptor[T], len(sk))
	for i := range sk {
		encs[i] = tfhe.NewEncryptorWithKey(params.Parameters, sk[i])
	}

	return &Decryptor[T]{
		Encoder:        tfhe.NewEncoder(params.Parameters),
		BaseEncryptors: encs,

		Parameters: params,

		buffer: newDecryptionBuffer(params),
	}
}

// newDecryptionBuffer creates a new decryptionBuffer.
func newDecryptionBuffer[T tfhe.TorusInt](params Parameters[T]) decryptionBuffer[T] {
	return decryptionBuffer[T]{
		ctLWE:  tfhe.NewLWECiphertext(params.Parameters),
		ctGLWE: tfhe.NewGLWECiphertext(params.Parameters),
		ptGLWE: tfhe.NewGLWEPlaintext(params.Parameters),
	}
}

// ShallowCopy returns a shallow copy of this Decryptor.
// Returned Decryptor is safe for concurrent use.
func (d *Decryptor[T]) ShallowCopy() *Decryptor[T] {
	encs := make([]*tfhe.Encryptor[T], len(d.BaseEncryptors))
	for i, enc := range d.BaseEncryptors {
		encs[i] = enc.ShallowCopy()
	}

	return &Decryptor[T]{
		Encoder:        d.Encoder,
		BaseEncryptors: encs,

		Parameters: d.Parameters,

		buffer: d.buffer,
	}
}

// PartyCount returns the number of parties in this Decryptor.
// This may be less than PartyCount in the Parameters.
func (d *Decryptor[T]) PartyCount() int {
	return len(d.BaseEncryptors)
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return d.DecodeLWE(d.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (d *Decryptor[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) tfhe.LWEPlaintext[T] {
	lweDimension := d.Parameters.Parameters.DefaultLWEDimension()

	d.buffer.ctLWE.Value[0] = ct.Value[0]
	for i := range d.BaseEncryptors {
		vec.CopyAssign(ct.Value[1+i*lweDimension:1+(i+1)*lweDimension], d.buffer.ctLWE.Value[1:])
		d.buffer.ctLWE.Value[0] = d.BaseEncryptors[i].DecryptLWEPlaintext(d.buffer.ctLWE).Value
	}
	return tfhe.LWEPlaintext[T]{Value: d.buffer.ctLWE.Value[0]}
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	d.DecryptGLWEPlaintextAssign(ct, d.buffer.ptGLWE)
	return d.DecodeGLWE(d.buffer.ptGLWE)
}

// DecryptGLWEAssign decrypts and decodes GLWE ciphertext to integer message and writes it to messagesOut.
func (d *Decryptor[T]) DecryptGLWEAssign(ct GLWECiphertext[T], messagesOut []int) {
	d.DecryptGLWEPlaintextAssign(ct, d.buffer.ptGLWE)
	d.DecodeGLWEAssign(d.buffer.ptGLWE, messagesOut)
}

// DecryptGLWEPlaintext decrypts GLWE ciphertext to GLWE plaintext.
func (d *Decryptor[T]) DecryptGLWEPlaintext(ct GLWECiphertext[T]) tfhe.GLWEPlaintext[T] {
	pt := tfhe.NewGLWEPlaintext(d.Parameters.Parameters)
	d.DecryptGLWEPlaintextAssign(ct, pt)
	return pt
}

// DecryptGLWEPlaintextAssign decrypts GLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (d *Decryptor[T]) DecryptGLWEPlaintextAssign(ct GLWECiphertext[T], ptOut tfhe.GLWEPlaintext[T]) {
	d.buffer.ctGLWE.Value[0].CopyFrom(ct.Value[0])
	for i := range d.BaseEncryptors {
		d.buffer.ctGLWE.Value[1].CopyFrom(ct.Value[1+i])
		d.BaseEncryptors[i].DecryptGLWEPlaintextAssign(d.buffer.ctGLWE, tfhe.GLWEPlaintext[T]{Value: d.buffer.ctGLWE.Value[0]})
	}
	ptOut.Value.CopyFrom(d.buffer.ctGLWE.Value[0])
}
