package tfhe

// BinaryEncoder encodes boolean messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
//
// BinaryEncoder is safe for concurrent use.
type BinaryEncoder[T TorusInt] struct {
	// Parameters is the parameters for this Encoder.
	Parameters Parameters[T]
	// BaseEncoder is a generic Encoder for this BinaryEncoder.
	BaseEncoder *Encoder[T]
}

// NewBinaryEncoder returns a initialized BinaryEncoder with given parameters.
func NewBinaryEncoder[T TorusInt](params Parameters[T]) *BinaryEncoder[T] {
	return &BinaryEncoder[T]{
		Parameters:  params,
		BaseEncoder: NewEncoder(params),
	}
}

// EncodeLWEBool encodes boolean message to LWE plaintext.
//
// Note that this is different from calling EncodeLWE with 0 or 1.
func (e *BinaryEncoder[T]) EncodeLWEBool(message bool) LWEPlaintext[T] {
	if message {
		return LWEPlaintext[T]{Value: 1 << (e.Parameters.logQ - 3)}
	}
	return LWEPlaintext[T]{Value: 7 << (e.Parameters.logQ - 3)}
}

// DecodeLWEBool decodes LWE plaintext to boolean message.
func (e *BinaryEncoder[T]) DecodeLWEBool(pt LWEPlaintext[T]) bool {
	return pt.Value < (1 << (e.Parameters.logQ - 1))
}
