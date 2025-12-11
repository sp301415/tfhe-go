package tfhe

// BinaryPublicEncryptor encrypts binary TFHE ciphertexts with public key.
// This is meant to be public, usually for servers.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
//
// BinaryEncryptor is not safe for concurrent use.
// Use [*BinaryPublicEncryptor.SafeCopy] to get a safe copy.
type BinaryPublicEncryptor[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryPublicEncryptor.
	*BinaryEncoder[T]
	// Params is parameters for this BinaryPublicEncryptor.
	Params Parameters[T]
	// Encryptor is a generic PublicEncryptor for this BinaryPublicEncryptor.
	Encryptor *PublicEncryptor[T]
}

// NewBinaryPublicEncryptor creates a new BinaryPublicEncryptor.
func NewBinaryPublicEncryptor[T TorusInt](params Parameters[T], pk PublicKey[T]) *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Params:        params,
		Encryptor:     NewPublicEncryptor(params, pk),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *BinaryPublicEncryptor[T]) SafeCopy() *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Params:        e.Params,
		Encryptor:     e.Encryptor.SafeCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.Encryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolTo encrypts boolean message to LWE ciphertexts.
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
