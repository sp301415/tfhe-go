package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// BinaryEncoder encodes boolean messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
type BinaryEncoder struct {
	Parameters  Parameters[uint32]
	BaseEncoder *Encoder[uint32]
}

// NewBinaryEncoder returns a initialized BinaryEncoder with given parameters.
func NewBinaryEncoder(params Parameters[uint32]) *BinaryEncoder {
	return &BinaryEncoder{
		Parameters:  params,
		BaseEncoder: NewEncoder[uint32](params),
	}
}

// EncodeLWEBool encodes boolean message to LWE plaintext.
//
// Note that this is different from calling EncodeLWE with 0 or 1.
func (e *BinaryEncoder) EncodeLWEBool(message bool) LWEPlaintext[uint32] {
	if message {
		return LWEPlaintext[uint32]{Value: 1 << e.Parameters.deltaLog}
	}
	return LWEPlaintext[uint32]{Value: (e.Parameters.messageModulus<<1 - 1) << e.Parameters.deltaLog}
}

// DecodeLWEBool decodes LWE plaintext to boolean message.
func (e *BinaryEncoder) DecodeLWEBool(pt LWEPlaintext[uint32]) bool {
	return pt.Value < (1 << 31)
}

// EncodeLWEBoolCiphertext trivially encodes boolean message to LWE ciphertext,
// with zero mask and no error.
// Resulting ciphertext is cryptographically insecure.
//
// Note that this is different from calling EncodeLWE with 0 or 1.
func (e *BinaryEncoder) EncodeLWEBoolCiphertext(message bool) LWECiphertext[uint32] {
	ct := NewLWECiphertext(e.Parameters)
	ct.Value[0] = e.EncodeLWEBool(message).Value
	return ct
}

// EncodeLWEBoolCiphertextAssign trivially encodes boolean message to LWE ciphertext,
// with zero mask and no error.
// Resulting ciphertext is cryptographically insecure.
//
// Note that this is different from calling EncodeLWE with 0 or 1.
func (e *BinaryEncoder) EncodeLWEBoolCiphertextAssign(message bool, ct LWECiphertext[uint32]) {
	vec.Fill(ct.Value[1:], 0)
	ct.Value[0] = e.EncodeLWEBool(message).Value
}
