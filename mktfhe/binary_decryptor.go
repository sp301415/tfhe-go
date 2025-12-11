package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

// BinaryDecryptor is a multi-key TFHE binary decryptor.
type BinaryDecryptor[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryDecryptor.
	*tfhe.BinaryEncoder[T]
	// Params is parameters for this BinaryDecryptor.
	Params Parameters[T]
	// Decryptor is a generic Decryptor for this BinaryDecryptor.
	Decryptor *Decryptor[T]
}

// NewBinaryDecryptor creates a new BinaryDecryptor.
func NewBinaryDecryptor[T tfhe.TorusInt](params Parameters[T], sk map[int]tfhe.SecretKey[T]) *BinaryDecryptor[T] {
	return &BinaryDecryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.subParams),
		Params:        params,
		Decryptor:     NewDecryptor(params, sk),
	}
}

// SafeCopy returns a thread-safe copy.
func (d *BinaryDecryptor[T]) SafeCopy() *BinaryDecryptor[T] {
	return &BinaryDecryptor[T]{
		BinaryEncoder: d.BinaryEncoder,
		Params:        d.Params,
		Decryptor:     d.Decryptor.SafeCopy(),
	}
}

// DecryptLWEBool decrypts LWE ciphertext to boolean message.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling DecryptLWE and comparing with 0.
func (d *BinaryDecryptor[T]) DecryptLWEBool(ct LWECiphertext[T]) bool {
	return d.DecodeLWEBool(d.Decryptor.DecryptLWEPlaintext(ct))
}

// DecryptLWEBits decrypts a slice of binary LWE ciphertext
// to integer message.
// The order of bits of LWE ciphertexts are assumed to be little-endian.
func (d *BinaryDecryptor[T]) DecryptLWEBits(ct []LWECiphertext[T]) int {
	var message int
	for i := len(ct) - 1; i >= 0; i-- {
		message <<= 1
		if d.DecryptLWEBool(ct[i]) {
			message += 1
		}
	}
	return message
}
