package tfhe

// BinaryEncryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
//
// BinaryEncryptor is not safe for concurrent use.
// Use [*BinaryEncryptor[T].ShallowCopy] to get a safe copy.
type BinaryEncryptor[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryEncryptor.
	*BinaryEncoder[T]
	// Parameters holds the parameters for this BinaryEncryptor.
	Parameters Parameters[T]
	// BaseEncryptor is a generic Encryptor for this BinaryEncryptor.
	BaseEncryptor *Encryptor[T]
}

// NewBinaryEncryptor returns a initialized BinaryEncryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewBinaryEncryptor[T TorusInt](params Parameters[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEncryptor: NewEncryptor(params),
	}
}

// NewBinaryEncryptorWithKey returns a initialized BinaryEncryptor with given parameters and key.
func NewBinaryEncryptorWithKey[T TorusInt](params Parameters[T], sk SecretKey[T]) *BinaryEncryptor[T] {
	return &BinaryEncryptor[T]{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEncryptor: NewEncryptorWithKey(params, sk),
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

// DecryptLWEBool decrypts LWE ciphertext to boolean value.
func (e *BinaryEncryptor[T]) DecryptLWEBool(ct LWECiphertext[T]) bool {
	return e.DecodeLWEBool(e.BaseEncryptor.DecryptLWEPlaintext(ct))
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

// GenPublicKey samples a new PublicKey.
func (e *BinaryEncryptor[T]) GenPublicKey() PublicKey[T] {
	return e.BaseEncryptor.GenPublicKey()
}

// PublicEncryptor returns a public encryptor for this BinaryEncryptor.
func (e *BinaryEncryptor[T]) PublicEncryptor() *BinaryPublicEncryptor[T] {
	return NewBinaryPublicEncryptor(e.Parameters, e.GenPublicKey())
}

// GenBootstrapKey samples a new bootstrapping key.
//
// This can take a long time.
// Use [*BinaryEncryptor[T].GenBootstrapKeyParallel] for better key generation performance.
func (e *BinaryEncryptor[T]) GenBootstrapKey() BootstrapKey[T] {
	return e.BaseEncryptor.GenBootstrapKey()
}

// GenBootstrapKeyParallel samples a new bootstrapping key in parallel.
func (e *BinaryEncryptor[T]) GenBootstrapKeyParallel() BootstrapKey[T] {
	return e.BaseEncryptor.GenBootstrapKeyParallel()
}

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use [*BinaryEncryptor[T].GenKeySwitchKeyForBootstrapParallel] for better key generation performance.
func (e *BinaryEncryptor[T]) GenKeySwitchKeyForBootstrap() KeySwitchKey[T] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrap()
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *BinaryEncryptor[T]) GenKeySwitchKeyForBootstrapParallel() KeySwitchKey[T] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrapParallel()
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*BinaryEncryptor[T].GenEvaluationKeyParallel] for better key generation performance.
func (e *BinaryEncryptor[T]) GenEvaluationKey() EvaluationKey[T] {
	return e.BaseEncryptor.GenEvaluationKey()
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *BinaryEncryptor[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return e.BaseEncryptor.GenEvaluationKeyParallel()
}

// BinaryPublicEncryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be public, only for clients.
//
// BinaryPublicEncryptor is not safe for concurrent use.
// Use [*BinaryPublicEncryptor.ShallowCopy] to get a safe copy.
type BinaryPublicEncryptor[T TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryPublicEncryptor.
	*BinaryEncoder[T]
	// Parameters holds the parameters for this BinaryPublicEncryptor.
	Parameters Parameters[T]
	// BaseEncryptor is a generic Encryptor for this BinaryPublicEncryptor.
	BaseEncryptor *PublicEncryptor[T]
}

// NewBinaryPublicEncryptor returns a initialized BinaryPublicEncryptor with given parameters.
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
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryPublicEncryptor[T]) EncryptLWEBool(message bool) LWECiphertext[T] {
	return e.BaseEncryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolAssign encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
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
