package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

// BinaryDecryptor is a multi-key TFHE binary decryptor.
type BinaryDecryptor[T tfhe.TorusInt] struct {
	// BinaryEncoder is an embedded encoder for this BinaryDecryptor.
	*tfhe.BinaryEncoder[T]
	// Parameters is the parameters for this BinaryDecryptor.
	Parameters Parameters[T]
	// BaseDecryptor is a generic Decryptor for this BinaryDecryptor.
	BaseDecryptor *Decryptor[T]
}

// NewBinaryDecryptor creates a new BinaryDecryptor.
func NewBinaryDecryptor[T tfhe.TorusInt](params Parameters[T], sk map[int]tfhe.SecretKey[T]) *BinaryDecryptor[T] {
	return &BinaryDecryptor[T]{
		BinaryEncoder: tfhe.NewBinaryEncoder(params.singleKeyParameters),
		Parameters:    params,
		BaseDecryptor: NewDecryptor(params, sk),
	}
}

// ShallowCopy returns a shallow copy of this BinaryDecryptor.
// Returned BinaryDecryptor is safe for concurrent use.
func (d *BinaryDecryptor[T]) ShallowCopy() *BinaryDecryptor[T] {
	return &BinaryDecryptor[T]{
		BinaryEncoder: d.BinaryEncoder,
		Parameters:    d.Parameters,
		BaseDecryptor: d.BaseDecryptor.ShallowCopy(),
	}
}

// DecryptLWEBool decrypts LWE ciphertext to boolean message.
// Like most languages, false == 0, and true == 1.
//
// Note that this is different from calling DecryptLWE and comparing with 0.
func (d *BinaryDecryptor[T]) DecryptLWEBool(ct LWECiphertext[T]) bool {
	return d.DecodeLWEBool(d.BaseDecryptor.DecryptLWEPlaintext(ct))
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
