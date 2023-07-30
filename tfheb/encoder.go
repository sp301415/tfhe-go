package tfheb

import "github.com/sp301415/tfhe/tfhe"

const (
	// PlaintextFalse is a plaintext value corresponding to false.
	// Equals to -1/8.
	PlaintextFalse = 7 << (32 - 3)
	// PlaintextTrue is a plaintext value corresponding to true.
	// Equals to 1/8.
	PlaintextTrue = 1 << (32 - 3)
)

// Encoder encodes boolean messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
type Encoder struct {
	Parameters tfhe.Parameters[uint32]
}

// NewEncoder returns a initialized Encoder with given parameters.
func NewEncoder(params tfhe.Parameters[uint32]) Encoder {
	return Encoder{
		Parameters: params,
	}
}

// EncodeLWEBool encodes boolean message to LWE plaintext.
//
// Note that this is DIFFERENT from calling EncodeLWE with 0 or 1.
func (e Encoder) EncodeLWEBool(message bool) tfhe.LWEPlaintext[uint32] {
	if message {
		return tfhe.LWEPlaintext[uint32]{Value: PlaintextTrue}
	}
	return tfhe.LWEPlaintext[uint32]{Value: PlaintextFalse}
}

// DecodeLWEBool decodes LWE plaintext to boolean message.
func (e Encoder) DecodeLWEBool(pt tfhe.LWEPlaintext[uint32]) bool {
	return pt.Value < (1 << 31)
}

// EncodeLWEBoolCiphertext trivially encodes boolean message to LWE ciphertext,
// with zero mask and no error.
// Resulting ciphertext is cryptographically insecure.
//
// Note that this is DIFFERENT from calling EncodeLWE with 0 or 1.
func (e Encoder) EncodeLWEBoolCiphertext(message bool) tfhe.LWECiphertext[uint32] {
	ct := tfhe.NewLWECiphertext(e.Parameters)
	ct.Value[0] = e.EncodeLWEBool(message).Value
	return ct
}

// EncodeLWEBoolCiphertextAssign trivially encodes boolean message to LWE ciphertext,
// with zero mask and no error.
// Resulting ciphertext is cryptographically insecure.
//
// Note that this is DIFFERENT from calling EncodeLWE with 0 or 1.
func (e Encoder) EncodeLWEBoolCiphertextAssign(message bool, ct tfhe.LWECiphertext[uint32]) {
	ct.Value[0] = e.EncodeLWEBool(message).Value
}
