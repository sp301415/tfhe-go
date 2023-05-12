package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// EvaluationKey is a public key for Evaluator,
// which consists of Bootstrapping Key and KeySwitching Key.
type EvaluationKey[T Tint] struct {
	// BootstrappingKey is a bootstrapping key.
	BootstrappingKey BootstrappingKey[T]
	// KeySwitchingKey is a keyswithcing key switching GLWE secret key -> LWE secret key.
	KeySwitchingKey KeySwitchingKey[T]
}

// Evaluater handles homomorphic operation of values.
// This is meant to be public.
//
//	eval := tfhe.NewEvaluater(params, evkey)
//	defer eval.Free()
type Evaluater[T Tint] struct {
	Parameters Parameters[T]

	PolyEvaluater      poly.Evaluater[T]
	FourierTransformer poly.FourierTransformer[T]

	evaluationKey EvaluationKey[T]

	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluater.
type evaluationBuffer[T Tint] struct {
	// glweFourierCtOutForExtProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	glweFourierCtOutForExtProd FourierGLWECiphertext[T]
	// glweCtForCMux holds ct1 - ct0 in CMux.
	glweCtForCMux GLWECiphertext[T]
}

// NewEvaluater creates a new Evaluater based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluater[T Tint](params Parameters[T], evkey EvaluationKey[T]) Evaluater[T] {
	evaluater := NewEvaluaterWithoutKey(params)
	evaluater.evaluationKey = EvaluationKey[T]{
		BootstrappingKey: evkey.BootstrappingKey,
		KeySwitchingKey:  evkey.KeySwitchingKey,
	}

	return evaluater
}

// NewEvaluaterWithoutKey initializes a new Evaluater without keys.
// If you try to bootstrap without keys, it will panic.
// You can supply evaluation key later by using SetEvaluationKey().
func NewEvaluaterWithoutKey[T Tint](params Parameters[T]) Evaluater[T] {
	return Evaluater[T]{
		Parameters: params,

		PolyEvaluater:      poly.NewEvaluater[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T Tint](params Parameters[T]) evaluationBuffer[T] {
	return evaluationBuffer[T]{
		glweFourierCtOutForExtProd: NewFourierGLWECiphertext(params),
		glweCtForCMux:              NewGLWECiphertext(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		Parameters: e.Parameters,

		PolyEvaluater:      e.PolyEvaluater.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		evaluationKey: e.evaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.AddInPlace(ct0.Value, ct1.Value, ctOut.Value)
}

// AddLWEAssign adds LWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.AddAssign(ct0.Value, ctOut.Value)
}

// AddGLWE adds two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.AddGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEInPlace adds two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.AddInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// AddGLWEAssign adds GLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.AddAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// SubGLWE subtracts two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) SubGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.SubGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubGLWEInPlace subtracts two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) SubGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.SubInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// SubGLWEAssign subtracts GLWE ciphertext ct0 from ctOut.
func (e Evaluater[T]) SubGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.SubAssign(ct0.Value[i], ctOut.Value[i])
	}
}

// ScalarMulGLWE multiplies p to ct0 and returns the result.
func (e Evaluater[T]) ScalarMulGLWE(ct0 GLWECiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ScalarMulGLWEInPlace(ct0, p, ctOut)
	return ctOut
}

// ScalarMulGLWEInPlace multiplies p to ct0 and writes to ctOut.
func (e Evaluater[T]) ScalarMulGLWEInPlace(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulInPlace(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulGLWEAssign multiplies p to ctOut.
func (e Evaluater[T]) ScalarMulGLWEAssign(p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulAssign(p, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign multiplies p to ct0 and adds to ctOut.
func (e Evaluater[T]) ScalarMulAddGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulAddAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}

// ScalarMulAddGLWEAssign multiplies p to ct0 and subtracts from ctOut.
func (e Evaluater[T]) ScalarMulSubGLWEAssign(ct0 GLWECiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulSubAssign(ct0.Value[i], p, ctOut.Value[i])
	}
}
