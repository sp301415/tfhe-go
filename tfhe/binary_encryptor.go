package tfhe

// BinaryEncryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
//
// BinaryEncryptor is not safe for concurrent use.
// Use [*BinaryEncryptor.ShallowCopy] to get a safe copy.
type BinaryEncryptor[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEncryptor.
	*BinaryEncoder[T]
	// Params is the parameters for this BinaryEncryptor.
	Params Parameters[T]
	// Encryptor is a generic Encryptor for this BinaryEncryptor.
	Encryptor *Encryptor[T]
}

// NewBinaryEncryptor returns a initialized BinaryEncryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewBinaryEncryptor[T TorusInt](params Parameters[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Params:        params,
		Encryptor:     NewEncryptor(params),
	}
}

// NewBinaryEncryptorWithKey returns a initialized BinaryEncryptor with given parameters and key.
func NewBinaryEncryptorWithKey[T TorusInt](params Parameters[T], sk SecretKey[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Params:        params,
		Encryptor:     NewEncryptorWithKey(params, sk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryEncryptor.
// Returned BinaryEncryptor is safe for concurrent use.
func (e *BinaryEncryptor[T]) ShallowCopy() *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: e.BinaryEncoder,
		Params:        e.Params,
		Encryptor:     e.Encryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.Encryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolTo encrypts boolean message to LWE ciphertexts and writes to ctOut.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor[T]) EncryptLWEBoolTo(ctOut LWECiphertext[T], message bool) {
	e.Encryptor.EncryptLWEPlaintextTo(ctOut, e.EncodeLWEBool(message))
}

// DecryptLWEBool decrypts LWE ciphertext to boolean value.
func (e *BinaryEncryptor[T]) DecryptLWEBool(ct LWECiphertext[T]) bool {
	return e.DecodeLWEBool(e.Encryptor.DecryptLWEPhase(ct))
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryEncryptor[T]) EncryptLWEBits(message, bits int) []LWECiphertext[T] {
	ctOut := make([]LWECiphertext[T], bits)
	e.EncryptLWEBitsTo(ctOut, message)
	return ctOut
}

// EncryptLWEBitsTo encrypts each bit of an integer message and writes the bits
// into ctOut in little-endian order. The output slice length determines how
// many bits are produced (the message will be truncated to that length).
func (e *BinaryEncryptor[T]) EncryptLWEBitsTo(ctOut []LWECiphertext[T], message int) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}

// DecryptLWEBits decrypts a slice of binary LWE ciphertext
// to integer message.
// The order of bits of LWE ciphertexts are assumed to be little-endian.
func (e *BinaryEncryptor[T]) DecryptLWEBits(ct []LWECiphertext[T]) int {
	var message int
	for i := len(ct) - 1; i >= 0; i-- {
		message <<= 1
		if e.DecryptLWEBool(ct[i]) {
			message += 1
		}
	}
	return message
}

// GenPublicKey samples a new public key.
//
// Panics when the parameters do not support public key encryption.
func (e *BinaryEncryptor[T]) GenPublicKey() PublicKey[T] {
	return e.Encryptor.GenPublicKey()
}

// PublicEncryptor returns a BinaryPublicEncryptor with the same parameters.
func (e *BinaryEncryptor[T]) PublicEncryptor() *BinaryPublicEncryptor[T] {
	return NewBinaryPublicEncryptor(e.Params, e.GenPublicKey())
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*BinaryEncryptor.GenEvaluationKeyParallel] for better key generation performance.
func (e *BinaryEncryptor[T]) GenEvaluationKey() EvaluationKey[T] {
	return e.Encryptor.GenEvaluationKey()
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *BinaryEncryptor[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return e.Encryptor.GenEvaluationKeyParallel()
}
