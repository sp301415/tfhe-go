package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// BinaryEncryptor is a multi-key variant of [tfhe.BinaryEncryptor].
type BinaryEncryptor[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEncryptor.
	*tfhe.BinaryEncoder[T]
	// Params is the parameters for this BinaryEncryptor.
	Params Parameters[T]
	// Encryptor is a generic Encryptor for this BinaryEncryptor.
	Encryptor *Encryptor[T]
}

// NewBinaryEncryptor creates a new BinaryEncryptor.
func NewBinaryEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.subParams),
		Params:        params,
		Encryptor:     NewEncryptor(params, idx, crsSeed),
	}
}

// NewBinaryEncryptorWithKey creates a new BinaryEncryptor with a given key.
func NewBinaryEncryptorWithKey[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte, sk tfhe.SecretKey[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.subParams),
		Params:        params,
		Encryptor:     NewEncryptorWithKey(params, idx, crsSeed, sk),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *BinaryEncryptor[T]) SafeCopy() *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Params:        e.Params,
		Encryptor:     e.Encryptor.SafeCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.Encryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolTo encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBoolTo(ctOut LWECiphertext[T], message bool) {
	e.Encryptor.EncryptLWEPlaintextTo(ctOut, e.EncodeLWEBool(message))
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryEncryptor[T]) EncryptLWEBits(message, bits int) []LWECiphertext[T] {
	ctOut := make([]LWECiphertext[T], bits)
	e.EncryptLWEBitsTo(ctOut, message)
	return ctOut
}

// EncryptLWEBitsTo encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of ctOut.
func (e *BinaryEncryptor[T]) EncryptLWEBitsTo(ctOut []LWECiphertext[T], message int) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}

// GenEvalKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenEvalKeyParallel] for better key generation performance.
func (e *BinaryEncryptor[T]) GenEvalKey() EvaluationKey[T] {
	return e.Encryptor.GenEvalKey()
}

// GenEvalKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *BinaryEncryptor[T]) GenEvalKeyParallel() EvaluationKey[T] {
	return e.Encryptor.GenEvalKeyParallel()
}

// GenPublicKey samples a new public key.
//
// Panics when the parameters do not support public key encryption.
func (e *BinaryEncryptor[T]) GenPublicKey() tfhe.PublicKey[T] {
	return e.Encryptor.GenPublicKey()
}

// PublicEncryptor returns a BinaryPublicEncryptor with the same parameters.
func (e *BinaryEncryptor[T]) PublicEncryptor() *BinaryPublicEncryptor[T] {
	return NewBinaryPublicEncryptor(e.Params, e.Encryptor.Index, e.GenPublicKey())
}
