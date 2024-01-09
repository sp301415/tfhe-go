package tfhe

// BinaryEncryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
type BinaryEncryptor struct {
	*BinaryEncoder
	Parameters    Parameters[uint32]
	BaseEncryptor *Encryptor[uint32]
}

// NewBinaryEncryptor returns a initialized BinaryEncryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewBinaryEncryptor(params Parameters[uint32]) *BinaryEncryptor {
	return &BinaryEncryptor{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEncryptor: NewEncryptor(params),
	}
}

// NewBinaryEncryptorWithKey returns a initialized BinaryEncryptor with given parameters and key.
func NewBinaryEncryptorWithKey(params Parameters[uint32], sk SecretKey[uint32]) *BinaryEncryptor {
	return &BinaryEncryptor{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEncryptor: NewEncryptorWithKey(params, sk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryEncryptor.
// Returned BinaryEncryptor is safe for concurrent use.
func (e *BinaryEncryptor) ShallowCopy() BinaryEncryptor {
	return BinaryEncryptor{
		BinaryEncoder: e.BinaryEncoder,
		Parameters:    e.Parameters,
		BaseEncryptor: e.BaseEncryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor) EncryptLWEBool(message bool) LWECiphertext[uint32] {
	return e.BaseEncryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolAssign encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *BinaryEncryptor) EncryptLWEBoolAssign(message bool, ct LWECiphertext[uint32]) {
	e.BaseEncryptor.EncryptLWEPlaintextAssign(e.EncodeLWEBool(message), ct)
}

// DecryptLWEBool decrypts LWE ciphertext to boolean value.
func (e *BinaryEncryptor) DecryptLWEBool(ct LWECiphertext[uint32]) bool {
	return e.DecodeLWEBool(e.BaseEncryptor.DecryptLWEPlaintext(ct))
}

// EncryptLWEBits encrypts each bits of an integer message.
// The order of the bits are little-endian.
func (e *BinaryEncryptor) EncryptLWEBits(message, bits int) []LWECiphertext[uint32] {
	cts := make([]LWECiphertext[uint32], bits)
	e.EncryptLWEBitsAssign(message, cts)
	return cts
}

// EncryptLWEBitsAssign encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of ctOut.
func (e *BinaryEncryptor) EncryptLWEBitsAssign(message int, ctOut []LWECiphertext[uint32]) {
	for i := 0; i < len(ctOut); i++ {
		ctOut[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}

// DecryptLWEBits decrypts a slice of binary LWE ciphertext
// to integer message.
// The order of bits of LWE ciphertexts are assumed to be little-endian.
func (e *BinaryEncryptor) DecryptLWEBits(ct []LWECiphertext[uint32]) int {
	var message int
	for i := len(ct) - 1; i >= 0; i-- {
		message <<= 1
		if e.DecryptLWEBool(ct[i]) {
			message += 1
		}
	}
	return message
}

// GenBootstrapKey samples a new bootstrapping key.
//
// This can take a long time.
// Use GenBootstrapKeyParallel for better key generation performance.
func (e *BinaryEncryptor) GenBootstrapKey() BootstrapKey[uint32] {
	return e.BaseEncryptor.GenBootstrapKey()
}

// GenBootstrapKeyParallel samples a new bootstrapping key in parallel.
func (e *BinaryEncryptor) GenBootstrapKeyParallel() BootstrapKey[uint32] {
	return e.BaseEncryptor.GenBootstrapKeyParallel()
}

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use GenKeySwitchKeyForBootstrapParallel for better key generation performance.
func (e *BinaryEncryptor) GenKeySwitchKeyForBootstrap() KeySwitchKey[uint32] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrap()
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *BinaryEncryptor) GenKeySwitchKeyForBootstrapParallel() KeySwitchKey[uint32] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrapParallel()
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use GenEvaluationKeyParallel for better key generation performance.
func (e *BinaryEncryptor) GenEvaluationKey() EvaluationKey[uint32] {
	return e.BaseEncryptor.GenEvaluationKey()
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *BinaryEncryptor) GenEvaluationKeyParallel() EvaluationKey[uint32] {
	return e.BaseEncryptor.GenEvaluationKeyParallel()
}
