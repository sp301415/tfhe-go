package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Decryptor is a multi-key TFHE decryptor.
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
	// GLWETransformer is an embedded GLWETransformer for this Decryptor.
	*GLWETransformer[T]
	// SingleKeyDecryptors are single-key Encryptors for this Decryptor.
	// If a secret key of a given index does not exist, it is nil.
	SingleKeyDecryptors []*tfhe.Encryptor[T]

	// Parameters is the parameters for the decryptor.
	Parameters Parameters[T]
	// PartyBitMap is a bitmap for parties.
	// If a party of a given index exists, it is true.
	PartyBitMap []bool

	// SecretKeys are the secret keys for this Decryptor.
	// This is shared with SingleKeyDecryptors.
	// If a secret key of a given index does not exist, it is empty.
	SecretKeys []tfhe.SecretKey[T]

	buffer decryptionBuffer[T]
}

// decryptionBuffer is a buffer for decryption.
type decryptionBuffer[T tfhe.TorusInt] struct {
	// ptGLWE is the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE is the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// ctLWESingle is the LWE ciphertext.
	ctLWESingle tfhe.LWECiphertext[T]
	// ctGLWESingle is the GLWE ciphertext.
	ctGLWESingle tfhe.GLWECiphertext[T]
}

// NewDecryptor creates a new Decryptor.
// Only indices between 0 and params.PartyCount is valid for sk.
func NewDecryptor[T tfhe.TorusInt](params Parameters[T], sk map[int]tfhe.SecretKey[T]) *Decryptor[T] {
	singleEncs := make([]*tfhe.Encryptor[T], len(sk))
	singleKeys := make([]tfhe.SecretKey[T], len(sk))
	partyBitMap := make([]bool, params.PartyCount())
	for i := range sk {
		singleEncs[i] = tfhe.NewEncryptorWithKey(params.singleKeyParameters, sk[i])
		singleKeys[i] = sk[i]
		partyBitMap[i] = true
	}

	return &Decryptor[T]{
		Encoder:             tfhe.NewEncoder(params.singleKeyParameters),
		GLWETransformer:     NewGLWETransformer[T](params.PolyDegree()),
		SingleKeyDecryptors: singleEncs,

		Parameters:  params,
		PartyBitMap: partyBitMap,

		SecretKeys: singleKeys,

		buffer: newDecryptionBuffer(params),
	}
}

// newDecryptionBuffer creates a new decryptionBuffer.
func newDecryptionBuffer[T tfhe.TorusInt](params Parameters[T]) decryptionBuffer[T] {
	return decryptionBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.singleKeyParameters),
		ctGLWE: NewGLWECiphertext(params),

		ctLWESingle:  tfhe.NewLWECiphertext(params.singleKeyParameters),
		ctGLWESingle: tfhe.NewGLWECiphertext(params.singleKeyParameters),
	}
}

// AddSecretKey adds a secret key to this Decryptor.
// If a secret key of a given index already exists, it is overwritten.
func (d *Decryptor[T]) AddSecretKey(idx int, sk tfhe.SecretKey[T]) {
	d.SingleKeyDecryptors[idx] = tfhe.NewEncryptorWithKey(d.Parameters.singleKeyParameters, sk)
	d.SecretKeys[idx] = sk
	d.PartyBitMap[idx] = true
}

// ShallowCopy returns a shallow copy of this Decryptor.
// Returned Decryptor is safe for concurrent use.
func (d *Decryptor[T]) ShallowCopy() *Decryptor[T] {
	decs := make([]*tfhe.Encryptor[T], d.Parameters.partyCount)
	for i, dec := range d.SingleKeyDecryptors {
		if dec != nil {
			decs[i] = dec.ShallowCopy()
		}
	}

	return &Decryptor[T]{
		Encoder:             d.Encoder,
		GLWETransformer:     d.GLWETransformer.ShallowCopy(),
		SingleKeyDecryptors: decs,

		Parameters:  d.Parameters,
		PartyBitMap: vec.Copy(d.PartyBitMap),

		SecretKeys: vec.Copy(d.SecretKeys),

		buffer: d.buffer,
	}
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return d.DecodeLWE(d.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (d *Decryptor[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) tfhe.LWEPlaintext[T] {
	pt := ct.Value[0]
	for i, ok := range d.PartyBitMap {
		if ok {
			ctMask := ct.Value[1+i*d.Parameters.singleKeyParameters.DefaultLWEDimension() : 1+(i+1)*d.Parameters.singleKeyParameters.DefaultLWEDimension()]
			pt += vec.Dot(ctMask, d.SingleKeyDecryptors[i].DefaultLWESecretKey().Value)
		}
	}
	return tfhe.LWEPlaintext[T]{Value: pt}
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
	pt := tfhe.NewGLWEPlaintext(d.Parameters.singleKeyParameters)
	d.DecryptGLWEPlaintextAssign(ct, pt)
	return pt
}

// DecryptGLWEPlaintextAssign decrypts GLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (d *Decryptor[T]) DecryptGLWEPlaintextAssign(ct GLWECiphertext[T], ptOut tfhe.GLWEPlaintext[T]) {
	d.buffer.ctGLWESingle.Value[0].CopyFrom(ct.Value[0])
	for i, ok := range d.PartyBitMap {
		if ok {
			d.buffer.ctGLWESingle.Value[1].CopyFrom(ct.Value[1+i])
			d.SingleKeyDecryptors[i].DecryptGLWEPhaseAssign(d.buffer.ctGLWESingle, tfhe.GLWEPlaintext[T]{Value: d.buffer.ctGLWESingle.Value[0]})
		}
	}
	ptOut.Value.CopyFrom(d.buffer.ctGLWESingle.Value[0])
}

// DecryptFourierGLWE decrypts and decodes FourierGLWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptFourierGLWE(ct FourierGLWECiphertext[T]) []int {
	return d.DecodeGLWE(d.DecryptFourierGLWEPlaintext(ct))
}

// DecryptFourierGLWEAssign decrypts and decodes FourierGLWE ciphertext to integer message and writes it to messagesOut.
func (d *Decryptor[T]) DecryptFourierGLWEAssign(ct FourierGLWECiphertext[T], messagesOut []int) {
	d.DecodeGLWEAssign(d.DecryptFourierGLWEPlaintext(ct), messagesOut)
}

// DecryptFourierGLWEPlaintext decrypts FourierGLWE ciphertext to GLWE plaintext.
func (d *Decryptor[T]) DecryptFourierGLWEPlaintext(ct FourierGLWECiphertext[T]) tfhe.GLWEPlaintext[T] {
	ptOut := tfhe.NewGLWEPlaintext(d.Parameters.singleKeyParameters)
	d.DecryptFourierGLWEPlaintextAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEPlaintextAssign decrypts FourierGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (d *Decryptor[T]) DecryptFourierGLWEPlaintextAssign(ct FourierGLWECiphertext[T], ptOut tfhe.GLWEPlaintext[T]) {
	d.ToGLWECiphertextAssign(ct, d.buffer.ctGLWE)
	d.DecryptGLWEPlaintextAssign(d.buffer.ctGLWE, ptOut)
}
