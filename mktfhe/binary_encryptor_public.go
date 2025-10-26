package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

// BinaryPublicEncryptor is a multi-key variant of [tfhe.BinaryPublicEncryptor].
type BinaryPublicEncryptor[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryPublicEncryptor.
	*tfhe.BinaryEncoder[T]
	// Params is the parameters for this BinaryPublicEncryptor.
	Params Parameters[T]
	// Encryptor is a generic PublicEncryptor for this BinaryPublicEncryptor.
	Encryptor *PublicEncryptor[T]
}

// NewBinaryPublicEncryptor creates a new BinaryPublicEncryptor.
func NewBinaryPublicEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, pk tfhe.PublicKey[T]) *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.subParams),
		Params:        params,
		Encryptor:     NewPublicEncryptor(params, idx, pk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryPublicEncryptor.
// Returned BinaryPublicEncryptor is safe for concurrent use.
func (e *BinaryPublicEncryptor[T]) ShallowCopy() *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Params:        e.Params,
		Encryptor:     e.Encryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.Encryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolTo encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBoolTo(ctOut LWECiphertext[T], message bool) {
	e.Encryptor.EncryptLWEPlaintextTo(ctOut, e.EncodeLWEBool(message))
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBits(message, bits int) []LWECiphertext[T] {
	ctOut := make([]LWECiphertext[T], bits)
	e.EncryptLWEBitsTo(ctOut, message)
	return ctOut
}

// EncryptLWEBitsTo encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of ctOut.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBitsTo(ctOut []LWECiphertext[T], message int) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}
