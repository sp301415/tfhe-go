package tfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// Encoder encodes integer messages to TFHE plaintexts.
// Encoder is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
//
// Encoder is safe for concurrent use.
type Encoder[T TorusInt] struct {
	// Params is the parameters for this Encoder.
	Params Parameters[T]
}

// NewEncoder returns a initialized Encoder with given parameters.
func NewEncoder[T TorusInt](params Parameters[T]) *Encoder[T] {
	return &Encoder[T]{
		Params: params,
	}
}

// EncodeLWE encodes integer message to LWE plaintext.
// Parameter's MessageModulus and Scale are used.
func (e *Encoder[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return e.EncodeLWECustom(message, e.Params.messageModulus, e.Params.scale)
}

// EncodeLWECustom encodes integer message to LWE plaintext
// using custom MessageModulus and Scale.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e *Encoder[T]) EncodeLWECustom(message int, messageModulus, scale T) LWEPlaintext[T] {
	encoded := T(message)
	if messageModulus != 0 {
		encoded %= messageModulus
	}
	return LWEPlaintext[T]{Value: encoded * scale}
}

// DecodeLWE decodes LWE plaintext to integer message.
// Parameter's MessageModulus and Scale are used.
func (e *Encoder[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return e.DecodeLWECustom(pt, e.Params.messageModulus, e.Params.scale)
}

// DecodeLWECustom decodes LWE plaintext to integer message
// using custom MessageModulus and Scale.
//
// If MessageModulus = 0, then it is automatically set to round(Q / scale).
func (e *Encoder[T]) DecodeLWECustom(pt LWEPlaintext[T], messageModulus, scale T) int {
	decoded := num.DivRound(pt.Value, scale)
	if messageModulus == 0 {
		messageModulus = T(math.Round(math.Exp2(float64(e.Params.logQ)) / float64(scale)))
	}
	return int(decoded % messageModulus)
}

// EncodeGLWE encodes up to Parameters.PolyRank integer messages into one GLWE plaintext.
// Parameter's MessageModulus and Scale are used.
//
//   - If len(messages) < PolyRank, the leftovers are padded with zero.
//   - If len(messages) > PolyRank, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Params)
	e.EncodeGLWETo(ptOut, messages)
	return ptOut
}

// EncodeGLWETo encodes up to Parameters.PolyRank integer messages into one GLWE plaintext.
// Parameter's MessageModulus and Scale are used.
//
//   - If len(messages) < PolyRank, the leftovers are padded with zero.
//   - If len(messages) > PolyRank, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWETo(ptOut GLWEPlaintext[T], messages []int) {
	e.EncodeGLWECustomTo(ptOut, messages, e.Params.messageModulus, e.Params.scale)
}

// EncodeGLWECustom encodes integer message to GLWE plaintext
// using custom MessageModulus and Scale.
//
//   - If MessageModulus = 0, then no modulus reduction is performed.
//   - If len(messages) < PolyRank, the leftovers are padded with zero.
//   - If len(messages) > PolyRank, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWECustom(messages []int, messageModulus, scale T) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Params)
	e.EncodeGLWECustomTo(ptOut, messages, messageModulus, scale)
	return ptOut
}

// EncodeGLWECustomTo encodes integer message to GLWE plaintext
// using custom MessageModulus and Scale.
//
//   - If MessageModulus = 0, then no modulus reduction is performed.
//   - If len(messages) < PolyRank, the leftovers are padded with zero.
//   - If len(messages) > PolyRank, the leftovers are discarded.
func (e *Encoder[T]) EncodeGLWECustomTo(ptOut GLWEPlaintext[T], messages []int, messageModulus, scale T) {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		ptOut.Value.Coeffs[i] = T(messages[i])
		if messageModulus != 0 {
			ptOut.Value.Coeffs[i] %= messageModulus
		}
		ptOut.Value.Coeffs[i] *= scale
	}
	vec.Fill(ptOut.Value.Coeffs[length:], 0)
}

// DecodeGLWE decodes GLWE plaintext to integer message.
// Parameter's MessageModulus and Scale are used.
// The returned messages are always of length PolyRank.
func (e *Encoder[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messagesOut := make([]int, e.Params.polyRank)
	e.DecodeGLWETo(messagesOut, pt)
	return messagesOut
}

// DecodeGLWETo decodes GLWE plaintext to integer message.
// Parameter's MessageModulus and Scale are used.
//
//   - If len(messagesOut) < PolyRank, the leftovers are discarded.
//   - If len(messagesOut) > PolyRank, only the first PolyRank elements are written.
func (e *Encoder[T]) DecodeGLWETo(messagesOut []int, pt GLWEPlaintext[T]) {
	e.DecodeGLWECustomTo(messagesOut, pt, e.Params.messageModulus, e.Params.scale)
}

// DecodeGLWECustom decodes GLWE plaintext to integer message
// using custom MessageModulus and Scale.
// The returned messages are always of length PolyRank.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e *Encoder[T]) DecodeGLWECustom(pt GLWEPlaintext[T], messageModulus, scale T) []int {
	messagesOut := make([]int, e.Params.polyRank)
	e.DecodeGLWECustomTo(messagesOut, pt, messageModulus, scale)
	return messagesOut
}

// DecodeGLWECustomTo decodes GLWE plaintext to integer message
// using custom MessageModulus and Scale.
//
//   - If MessageModulus = 0, then it is automatically set to round(Q / scale).
//   - If len(messagesOut) < PolyRank, the leftovers are discarded.
//   - If len(messagesOut) > PolyRank, only the first PolyRank elements are written.
func (e *Encoder[T]) DecodeGLWECustomTo(messagesOut []int, pt GLWEPlaintext[T], messageModulus, scale T) {
	length := num.Min(e.Params.polyRank, len(messagesOut))
	for i := 0; i < length; i++ {
		decoded := num.DivRound(pt.Value.Coeffs[i], scale)
		if messageModulus == 0 {
			messageModulus = T(math.Round(math.Exp2(float64(e.Params.logQ)) / float64(scale)))
		}
		messagesOut[i] = int(decoded % messageModulus)
	}
}
