package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

// BinaryEncryptor is a Multi-Key variant of [tfhe.BinaryEncryptor].
type BinaryEncryptor[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEncryptor.
	*tfhe.BinaryEncoder[T]
	// Parameters holds the parameters for this BinaryEncryptor.
	Parameters Parameters[T]
	// BaseEncryptor is a generic Encryptor for this BinaryEncryptor.
	BaseEncryptor *Encryptor[T]
}

// NewBinaryEncryptor creates a new BinaryEncryptor.
func NewBinaryEncryptor[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte) BinaryEncryptor[T] {
	return BinaryEncryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.Parameters),
		Parameters:    params,
		BaseEncryptor: NewEncryptor(params, idx, crsSeed),
	}
}

// NewBinaryEncryptorWithKey creates a new BinaryEncryptor with a given key.
func NewBinaryEncryptorWithKey[T tfhe.TorusInt](params Parameters[T], idx int, crsSeed []byte, sk tfhe.SecretKey[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.Parameters),
		Parameters:    params,
		BaseEncryptor: NewEncryptorWithKey(params, idx, crsSeed, sk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryEncryptor.
// Returned BinaryEncryptor is safe for concurrent use.
func (e *BinaryEncryptor[T]) ShallowCopy() *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Parameters:    e.Parameters,
		BaseEncryptor: e.BaseEncryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.BaseEncryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolAssign encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBoolAssign(message bool, ct LWECiphertext[T]) {
	e.BaseEncryptor.EncryptLWEPlaintextAssign(e.EncodeLWEBool(message), ct)
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryEncryptor[T]) EncryptLWEBits(message, bits int) []LWECiphertext[T] {
	cts := make([]LWECiphertext[T], bits)
	e.EncryptLWEBitsAssign(message, cts)
	return cts
}

// EncryptLWEBitsAssign encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of ctOut.
func (e *BinaryEncryptor[T]) EncryptLWEBitsAssign(message int, ctOut []LWECiphertext[T]) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}
