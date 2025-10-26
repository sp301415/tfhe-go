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
	// SubDecryptors are single-key Encryptors for this Decryptor.
	// If a secret key of a given index does not exist, it is nil.
	SubDecryptors []*tfhe.Encryptor[T]

	// Params is the parameters for the decryptor.
	Params Parameters[T]
	// PartyBitMap is a bitmap for parties.
	// If a party of a given index exists, it is true.
	PartyBitMap []bool

	// SecretKeys are the secret keys for this Decryptor.
	// This is shared with SingleKeyDecryptors.
	// If a secret key of a given index does not exist, it is empty.
	SecretKeys []tfhe.SecretKey[T]

	buf decryptorBuffer[T]
}

// decryptorBuffer is a buffer for decryption.
type decryptorBuffer[T tfhe.TorusInt] struct {
	// ptGLWE is the GLWE plaintext.
	ptGLWE tfhe.GLWEPlaintext[T]
	// ctGLWE is the GLWE ciphertext.
	ctGLWE GLWECiphertext[T]

	// ctSubLWE is the LWE ciphertext.
	ctSubLWE tfhe.LWECiphertext[T]
	// ctSubGLWE is the GLWE ciphertext.
	ctSubGLWE tfhe.GLWECiphertext[T]
}

// NewDecryptor creates a new Decryptor.
// Only indices between 0 and params.PartyCount is valid for sk.
func NewDecryptor[T tfhe.TorusInt](params Parameters[T], sk map[int]tfhe.SecretKey[T]) *Decryptor[T] {
	singleEncs := make([]*tfhe.Encryptor[T], len(sk))
	singleKeys := make([]tfhe.SecretKey[T], len(sk))
	partyBitMap := make([]bool, params.PartyCount())
	for i := range sk {
		singleEncs[i] = tfhe.NewEncryptorWithKey(params.subParams, sk[i])
		singleKeys[i] = sk[i]
		partyBitMap[i] = true
	}

	return &Decryptor[T]{
		Encoder:         tfhe.NewEncoder(params.subParams),
		GLWETransformer: NewGLWETransformer[T](params.PolyRank()),
		SubDecryptors:   singleEncs,

		Params:      params,
		PartyBitMap: partyBitMap,

		SecretKeys: singleKeys,

		buf: newDecryptorBuffer(params),
	}
}

// newDecryptorBuffer creates a new decryptorBuffer.
func newDecryptorBuffer[T tfhe.TorusInt](params Parameters[T]) decryptorBuffer[T] {
	return decryptorBuffer[T]{
		ptGLWE: tfhe.NewGLWEPlaintext(params.subParams),
		ctGLWE: NewGLWECiphertext(params),

		ctSubLWE:  tfhe.NewLWECiphertext(params.subParams),
		ctSubGLWE: tfhe.NewGLWECiphertext(params.subParams),
	}
}

// AddSecretKey adds a secret key to this Decryptor.
// If a secret key of a given index already exists, it is overwritten.
func (d *Decryptor[T]) AddSecretKey(idx int, sk tfhe.SecretKey[T]) {
	d.SubDecryptors[idx] = tfhe.NewEncryptorWithKey(d.Params.subParams, sk)
	d.SecretKeys[idx] = sk
	d.PartyBitMap[idx] = true
}

// ShallowCopy returns a shallow copy of this Decryptor.
// Returned Decryptor is safe for concurrent use.
func (d *Decryptor[T]) ShallowCopy() *Decryptor[T] {
	decs := make([]*tfhe.Encryptor[T], d.Params.partyCount)
	for i, dec := range d.SubDecryptors {
		if dec != nil {
			decs[i] = dec.ShallowCopy()
		}
	}

	return &Decryptor[T]{
		Encoder:         d.Encoder,
		GLWETransformer: d.GLWETransformer.ShallowCopy(),
		SubDecryptors:   decs,

		Params:      d.Params,
		PartyBitMap: vec.Copy(d.PartyBitMap),

		SecretKeys: vec.Copy(d.SecretKeys),

		buf: d.buf,
	}
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return d.DecodeLWE(d.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (d *Decryptor[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) tfhe.LWEPlaintext[T] {
	ptOut := ct.Value[0]
	for i, ok := range d.PartyBitMap {
		if ok {
			ctMask := ct.Value[1+i*d.Params.subParams.DefaultLWEDimension() : 1+(i+1)*d.Params.subParams.DefaultLWEDimension()]
			ptOut += vec.Dot(ctMask, d.SubDecryptors[i].DefaultLWESecretKey().Value)
		}
	}
	return tfhe.LWEPlaintext[T]{Value: ptOut}
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	d.DecryptGLWEPhaseTo(d.buf.ptGLWE, ct)
	return d.DecodeGLWE(d.buf.ptGLWE)
}

// DecryptGLWETo decrypts and decodes GLWE ciphertext to integer message and writes it to messagesOut.
func (d *Decryptor[T]) DecryptGLWETo(messagesOut []int, ct GLWECiphertext[T]) {
	d.DecryptGLWEPhaseTo(d.buf.ptGLWE, ct)
	d.DecodeGLWETo(messagesOut, d.buf.ptGLWE)
}

// DecryptGLWEPhase decrypts GLWE ciphertext to GLWE plaintext.
func (d *Decryptor[T]) DecryptGLWEPhase(ct GLWECiphertext[T]) tfhe.GLWEPlaintext[T] {
	ptOut := tfhe.NewGLWEPlaintext(d.Params.subParams)
	d.DecryptGLWEPhaseTo(ptOut, ct)
	return ptOut
}

// DecryptGLWEPhaseTo decrypts GLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (d *Decryptor[T]) DecryptGLWEPhaseTo(ptOut tfhe.GLWEPlaintext[T], ct GLWECiphertext[T]) {
	d.buf.ctSubGLWE.Value[0].CopyFrom(ct.Value[0])
	for i, ok := range d.PartyBitMap {
		if ok {
			d.buf.ctSubGLWE.Value[1].CopyFrom(ct.Value[1+i])
			d.SubDecryptors[i].DecryptGLWEPhaseTo(tfhe.GLWEPlaintext[T]{Value: d.buf.ctSubGLWE.Value[0]}, d.buf.ctSubGLWE)
		}
	}
	ptOut.Value.CopyFrom(d.buf.ctSubGLWE.Value[0])
}

// DecryptFFTGLWE decrypts and decodes FFTGLWE ciphertext to integer message.
func (d *Decryptor[T]) DecryptFFTGLWE(ct FFTGLWECiphertext[T]) []int {
	return d.DecodeGLWE(d.DecryptFFTGLWEPhase(ct))
}

// DecryptFFTGLWETo decrypts and decodes FFTGLWE ciphertext to integer message and writes it to messagesOut.
func (d *Decryptor[T]) DecryptFFTGLWETo(messagesOut []int, ct FFTGLWECiphertext[T]) {
	d.DecodeGLWETo(messagesOut, d.DecryptFFTGLWEPhase(ct))
}

// DecryptFFTGLWEPhase decrypts FFTGLWE ciphertext to GLWE plaintext.
func (d *Decryptor[T]) DecryptFFTGLWEPhase(ct FFTGLWECiphertext[T]) tfhe.GLWEPlaintext[T] {
	ptOut := tfhe.NewGLWEPlaintext(d.Params.subParams)
	d.DecryptFFTGLWEPhaseTo(ptOut, ct)
	return ptOut
}

// DecryptFFTGLWEPhaseTo decrypts FFTGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (d *Decryptor[T]) DecryptFFTGLWEPhaseTo(ptOut tfhe.GLWEPlaintext[T], ct FFTGLWECiphertext[T]) {
	d.ToGLWECiphertextTo(d.buf.ctGLWE, ct)
	d.DecryptGLWEPhaseTo(ptOut, d.buf.ctGLWE)
}
