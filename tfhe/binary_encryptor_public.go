package tfhe

// BinaryPublicEncryptor encrypts binary TFHE ciphertexts with public key.
// This is meant to be public, usually for servers.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
//
// BinaryEncryptor is not safe for concurrent use.
// Use [*BinaryPublicEncryptor.ShallowCopy] to get a safe copy.
type BinaryPublicEncryptor[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryPublicEncryptor.
	*BinaryEncoder[T]
	// Parameters is the parameters for this BinaryPublicEncryptor.
	Parameters Parameters[T]
	// BaseEncryptor is a generic PublicEncryptor for this BinaryPublicEncryptor.
	BaseEncryptor *PublicEncryptor[T]
}

// NewBinaryPublicEncryptor allocates a new BinaryPublicEncryptor.
func NewBinaryPublicEncryptor[T TorusInt](params Parameters[T], pk PublicKey[T]) *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEncryptor: NewPublicEncryptor(params, pk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryPublicEncryptor.
// Returned BinaryPublicEncryptor is safe for concurrent use.
func (e *BinaryPublicEncryptor[T]) ShallowCopy() *BinaryPublicEncryptor[T] {
	return &BinaryPublicEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Parameters:    e.Parameters,
		BaseEncryptor: e.BaseEncryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.BaseEncryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolAssign encrypts boolean message to LWE ciphertexts.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBoolAssign(message bool, ct LWECiphertext[T]) {
	e.BaseEncryptor.EncryptLWEPlaintextAssign(e.EncodeLWEBool(message), ct)
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBits(message, bits int) []LWECiphertext[T] {
	cts := make([]LWECiphertext[T], bits)
	e.EncryptLWEBitsAssign(message, cts)
	return cts
}

// EncryptLWEBitsAssign encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of ctOut.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBitsAssign(message int, ctOut []LWECiphertext[T]) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}
