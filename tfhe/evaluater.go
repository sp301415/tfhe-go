package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
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
type Evaluater[T Tint] struct {
	Parameters Parameters[T]

	polyEvaluater poly.Evaluater[T]

	evaluationKey EvaluationKey[T]
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

		polyEvaluater: poly.NewEvaluater[T](params.polyDegree),
	}
}

// Decompose decomposes x with respect to decompParams.
// Equivalant to decompParams.Decompose().
func (e Evaluater[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	return decompParams.Decompose(x)
}

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
}

// AddLWEAssign adds LWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddLWEAssign(ct0, ctOut LWECiphertext[T]) {
	e.AddLWEInPlace(ct0, ctOut, ctOut)
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
		e.polyEvaluater.AddInPlace(ct0.Value[i], ct1.Value[i], ctOut.Value[i])
	}
}

// AddGLWEAssign adds GLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	e.AddGLWEInPlace(ct0, ctOut, ctOut)
}
