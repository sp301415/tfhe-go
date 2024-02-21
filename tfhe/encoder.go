package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// Encoder encodes integer messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
//
// Encoder is safe for concurrent use.
type Encoder[T TorusInt] struct {
	// Parameters holds parameters for this Encoder.
	Parameters Parameters[T]
}

// NewEncoder returns a initialized Encoder with given parameters.
func NewEncoder[T TorusInt](params Parameters[T]) *Encoder[T] {
	return &Encoder[T]{
		Parameters: params,
	}
}

// EncodeLWE encodes integer message to LWE plaintext.
// Parameter's MessageModulus and Delta are used.
func (e *Encoder[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog}
}

// EncodeLWECustom encodes integer message to LWE plaintext
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e *Encoder[T]) EncodeLWECustom(message int, messageModulus, delta T) LWEPlaintext[T] {
	encoded := T(message)
	if messageModulus != 0 {
		encoded %= messageModulus
	}
	return LWEPlaintext[T]{Value: encoded * delta}
}

// DecodeLWE decodes LWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
func (e *Encoder[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatioBits(pt.Value, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// DecodeLWECustom decodes LWE plaintext to integer message
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e *Encoder[T]) DecodeLWECustom(pt LWEPlaintext[T], messageModulus, delta T) int {
	decoded := num.RoundRatio(pt.Value, delta)
	if messageModulus != 0 {
		decoded %= messageModulus
	}
	return int(decoded)
}

// EncodeGLWE encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
// Parameter's MessageModulus and Delta are used.
//
//   - If len(messages) < PolyDegree, the leftovers are padded with zero.
//   - If len(messages) > PolyDegree, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.EncodeGLWEAssign(messages, pt)
	return pt
}

// EncodeGLWEAssign encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
// Parameter's MessageModulus and Delta are used.
//
//   - If len(messages) < PolyDegree, the leftovers are padded with zero.
//   - If len(messages) > PolyDegree, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWEAssign(messages []int, pt GLWEPlaintext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		pt.Value.Coeffs[i] = (T(messages[i]) % e.Parameters.messageModulus) << e.Parameters.deltaLog
	}
	vec.Fill(pt.Value.Coeffs[length:], 0)
}

// EncodeGLWECustom encodes integer message to GLWE plaintext
// using custom MessageModulus and Delta.
//
//   - If MessageModulus = 0, then no modulus reduction is performed.
//   - If len(messages) < PolyDegree, the leftovers are padded with zero.
//   - If len(messages) > PolyDegree, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWECustom(messages []int, messageModulus, delta T) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.EncodeGLWECustomAssign(messages, messageModulus, delta, pt)
	return pt
}

// EncodeGLWECustomAssign encodes integer message to GLWE plaintext
// using custom MessageModulus and Delta.
//
//   - If MessageModulus = 0, then no modulus reduction is performed.
//   - If len(messages) < PolyDegree, the leftovers are padded with zero.
//   - If len(messages) > PolyDegree, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWECustomAssign(messages []int, messageModulus, delta T, pt GLWEPlaintext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		pt.Value.Coeffs[i] = T(messages[i])
		if messageModulus != 0 {
			pt.Value.Coeffs[i] %= messageModulus
		}
		pt.Value.Coeffs[i] *= delta
	}
	vec.Fill(pt.Value.Coeffs[length:], 0)
}

// DecodeGLWE decodes GLWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
// The returned messages are always of length PolyDegree.
func (e *Encoder[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	e.DecodeGLWEAssign(pt, messages)
	return messages
}

// DecodeGLWEAssign decodes GLWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
//
//   - If len(messagesOut) < PolyDegree, the leftovers are discarded.
//   - If len(messagesOut) > PolyDegree, only the first PolyDegree elements are written.
func (e *Encoder[T]) DecodeGLWEAssign(pt GLWEPlaintext[T], messagesOut []int) {
	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int((num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog) % e.Parameters.messageModulus))
	}
}

// DecodeGLWECustom decodes GLWE plaintext to integer message
// using custom MessageModulus and Delta.
// The returned messages are always of length PolyDegree.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e *Encoder[T]) DecodeGLWECustom(pt GLWEPlaintext[T], messageModulus, delta T) []int {
	messages := make([]int, e.Parameters.polyDegree)
	e.DecodeGLWEAssign(pt, messages)
	return messages
}

// DecodeGLWECustomAssign decodes GLWE plaintext to integer message
// using custom MessageModulus and Delta.
//
//   - If MessageModulus = 0, then no modulus reduction is performed.
//   - If len(messagesOut) < PolyDegree, the leftovers are discarded.
//   - If len(messagesOut) > PolyDegree, only the first PolyDegree elements are written.
func (e *Encoder[T]) DecodeGLWECustomAssign(pt GLWEPlaintext[T], messageModulus, delta T, messagesOut []int) {
	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		decoded := num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog)
		if messageModulus != 0 {
			decoded %= messageModulus
		}
		messagesOut[i] = int(decoded)
	}
}
