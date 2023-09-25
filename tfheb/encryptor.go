package tfheb

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// Encryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
type Encryptor struct {
	*Encoder
	Parameters    tfhe.Parameters[uint32]
	BaseEncryptor *tfhe.Encryptor[uint32]
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor(params tfhe.Parameters[uint32]) *Encryptor {
	return &Encryptor{
		Encoder:       NewEncoder(params),
		Parameters:    params,
		BaseEncryptor: tfhe.NewEncryptor(params),
	}
}

// ShallowCopy returns a shallow copy of this Encryptor.
// Returned Encryptor is safe for concurrent use.
func (e *Encryptor) ShallowCopy() Encryptor {
	return Encryptor{
		Encoder:       e.Encoder,
		Parameters:    e.Parameters,
		BaseEncryptor: e.BaseEncryptor.ShallowCopy(),
	}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *Encryptor) EncryptLWEBool(message bool) tfhe.LWECiphertext[uint32] {
	return e.BaseEncryptor.EncryptLWEPlaintext(e.EncodeLWEBool(message))
}

// EncryptLWEBoolAssign encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling EncryptLWE with 0 or 1.
func (e *Encryptor) EncryptLWEBoolAssign(message bool, ct tfhe.LWECiphertext[uint32]) {
	e.BaseEncryptor.EncryptLWEPlaintextAssign(e.EncodeLWEBool(message), ct)
}

// DecryptLWEBool decrypts LWE ciphertext to boolean value.
func (e *Encryptor) DecryptLWEBool(ct tfhe.LWECiphertext[uint32]) bool {
	return e.DecodeLWEBool(e.BaseEncryptor.DecryptLWEPlaintext(ct))
}

// EncryptLWEBits encrypts each bits of an integer message.
// The resulting slice of LWE ciphertexts always has length 64.
// The order of the bits are little-endian.
func (e *Encryptor) EncryptLWEBits(message int) []tfhe.LWECiphertext[uint32] {
	cts := make([]tfhe.LWECiphertext[uint32], 64)
	e.EncryptLWEBitsAssign(message, cts)
	return cts
}

// EncryptLWEBitsAssign encrypts each bits of an integer message.
// The order of the bits are little-endian,
// and will be cut by the length of cts.
func (e *Encryptor) EncryptLWEBitsAssign(message int, cts []tfhe.LWECiphertext[uint32]) {
	for i := 0; i < len(cts); i++ {
		cts[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
}

// DecryptLWEBits decrypts a slice of binary LWE ciphertext
// to integer message.
// The order of bits of LWE ciphertexts are assumed to be little-endian.
func (e *Encryptor) DecryptLWEBits(cts []tfhe.LWECiphertext[uint32]) int {
	var msg int
	for i := len(cts) - 1; i >= 0; i-- {
		msg <<= 1
		if e.DecryptLWEBool(cts[i]) {
			msg += 1
		}
	}
	return msg
}

// GenBootstrapKey samples a new bootstrapping key.
//
// This can take a long time.
// Use GenBootstrapKeyParallel for better key generation performance.
func (e *Encryptor) GenBootstrapKey() tfhe.BootstrapKey[uint32] {
	return e.BaseEncryptor.GenBootstrapKey()
}

// GenBootstrapKeyParallel samples a new bootstrapping key in parallel.
func (e *Encryptor) GenBootstrapKeyParallel() tfhe.BootstrapKey[uint32] {
	return e.BaseEncryptor.GenBootstrapKeyParallel()
}

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use GenKeySwitchKeyForBootstrapParallel for better key generation performance.
func (e *Encryptor) GenKeySwitchKeyForBootstrap() tfhe.KeySwitchKey[uint32] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrap()
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor) GenKeySwitchKeyForBootstrapParallel() tfhe.KeySwitchKey[uint32] {
	return e.BaseEncryptor.GenKeySwitchKeyForBootstrapParallel()
}

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use GenEvaluationKeyParallel for better key generation performance.
func (e *Encryptor) GenEvaluationKey() tfhe.EvaluationKey[uint32] {
	return e.BaseEncryptor.GenEvaluationKey()
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *Encryptor) GenEvaluationKeyParallel() tfhe.EvaluationKey[uint32] {
	return e.BaseEncryptor.GenEvaluationKeyParallel()
}
