package tfheb

import (
	"github.com/sp301415/tfhe/tfhe"
)

const (
	// PlaintextFalse is a plaintext value corresponding to false.
	// Equals to -1/8.
	PlaintextFalse = 7 << (32 - 3)
	// PlaintextTrue is a plaintext value corresponding to true.
	// Equals to 1/8.
	PlaintextTrue = 1 << (32 - 3)
)

// Encryptor encrypts binary TFHE plaintexts and ciphertexts.
// This is meant to be private, only for clients.
type Encryptor struct {
	tfhe.Encryptor[uint32]
}

// NewEncryptor returns a initialized Encryptor with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncryptor(params tfhe.Parameters[uint32]) Encryptor {
	return Encryptor{Encryptor: tfhe.NewEncryptor(params)}
}

// EncryptLWEBool encrypts boolean message to LWE ciphertexts.
// Like most languages, false == 0, and true == 1.
//
// Note that this is DIFFERENT from calling EncryptLWE with 0 or 1.
func (e Encryptor) EncryptLWEBool(message bool) tfhe.LWECiphertext[uint32] {
	if message {
		return e.EncryptLWEPlaintext(tfhe.LWEPlaintext[uint32]{Value: PlaintextTrue})
	}
	return e.EncryptLWEPlaintext(tfhe.LWEPlaintext[uint32]{Value: PlaintextFalse})
}

// DecryptLWEBool decrypts LWE ciphertext to boolean value.
func (e Encryptor) DecryptLWEBool(ct tfhe.LWECiphertext[uint32]) bool {
	return e.DecryptLWEPlaintext(ct).Value < (1 << 31)
}

// EncryptLWEBits encrypts each bits of an integer message.
// The resulting slice of LWE ciphertexts always has length 64.
// The order of the bits are little-endian.
func (e Encryptor) EncryptLWEBits(message int) []tfhe.LWECiphertext[uint32] {
	cts := make([]tfhe.LWECiphertext[uint32], 64)
	for i := 0; i < 64; i++ {
		cts[i] = e.EncryptLWEBool(message&1 == 1)
		message >>= 1
	}
	return cts
}

// DecryptLWEBits decrypts a slice of binary LWE ciphertext
// to integer message.
// The order of bits of LWE ciphertexts are assumed to be little-endian.
func (e Encryptor) DecryptLWEBits(cts []tfhe.LWECiphertext[uint32]) int {
	var msg int
	for i := len(cts) - 1; i >= 0; i-- {
		msg <<= 1
		if e.DecryptLWEBool(cts[i]) {
			msg += 1
		}
	}
	return msg
}
