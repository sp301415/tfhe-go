package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
)

// Encoder encodes integer messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
type Encoder[T Tint] struct {
	Parameters Parameters[T]
}

// NewEncoder returns a initialized Encoder with given parameters.
func NewEncoder[T Tint](params Parameters[T]) Encoder[T] {
	return Encoder[T]{
		Parameters: params,
	}
}

// EncodeLWE encodes integer message to LWE plaintext.
// Parameter's MessageModulus and Delta are used.
func (e Encoder[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog}
}

// EncodeLWECustom encodes integer message to LWE plaintext
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e Encoder[T]) EncodeLWECustom(message int, messageModulus, delta T) LWEPlaintext[T] {
	encoded := T(message)
	if messageModulus != 0 {
		encoded %= messageModulus
	}
	return LWEPlaintext[T]{Value: encoded * delta}
}

// DecodeLWE decodes LWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
func (e Encoder[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatioBits(pt.Value, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// DecodeLWECustom decodes LWE plaintext to integer message
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e Encoder[T]) DecodeLWECustom(pt LWEPlaintext[T], messageModulus, delta T) int {
	decoded := num.RoundRatio(pt.Value, delta)
	if messageModulus != 0 {
		decoded %= messageModulus
	}
	return int(decoded)
}

// EncodeGLWE encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
// Parameter's MessageModulus and Delta are used.
//
// If len(messages) < PolyDegree, the leftovers are padded with zero.
// If len(messages) > PolyDegree, the leftovers are discarded.
func (e Encoder[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = (T(messages[i]) % e.Parameters.messageModulus) << e.Parameters.deltaLog
	}
	return pt
}

// EncodeGLWECustom encodes integer message to GLWE plaintext
// using custom MessageModulus and Delta.
//
//	-If MessageModulus = 0, then no modulus reduction is performed.
//	-If len(messages) < PolyDegree, the leftovers are padded with zero.
//	-If len(messages) > PolyDegree, the leftovers are discarded.
func (e Encoder[T]) EncodeGLWECustom(messages []int, messageModulus, delta T) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i])
		if messageModulus != 0 {
			pt.Value.Coeffs[i] %= messageModulus
		}
		pt.Value.Coeffs[i] *= delta
	}
	return pt
}

// DecodeGLWE decodes GLWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
// The returned messages are always of length PolyDegree.
func (e Encoder[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int((num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog) % e.Parameters.messageModulus))
	}
	return messages
}

// DecodeGLWECustom decodes GLWE plaintext to integer message
// using custom MessageModulus and Delta.
// The returned messages are always of length PolyDegree.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e Encoder[T]) DecodeGLWECustom(pt GLWEPlaintext[T], messageModulus, delta T) []int {
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		decoded := num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog)
		if messageModulus != 0 {
			decoded %= messageModulus
		}
		messages[i] = int(decoded)
	}
	return messages
}
