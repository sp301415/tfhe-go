package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// EvaluationKey is a public key for Evaluator,
// which consists of Bootstrapping Key and Keyswitching Key.
type EvaluationKey[T Tint] struct {
	// BootstrappingKey is a bootstrapping key.
	BootstrappingKey BootstrappingKey[T]
	// KeyswitchingKey is a keyswithcing key switching GLWE secret key -> LWE secret key.
	KeyswitchingKey KeyswitchingKey[T]
}

// Evaluater handles homomorphic operation of values.
// This is meant to be public.
type Evaluater[T Tint] struct {
	Parameters Parameters[T]

	polyEvaluater poly.Evaluater[T]

	evaluationKey EvaluationKey[T]
}

// NewEvaluater creates a new Evaluater based on parameters.
func NewEvaluater[T Tint](params Parameters[T], evkey EvaluationKey[T]) Evaluater[T] {
	return Evaluater[T]{
		Parameters: params,

		polyEvaluater: poly.NewEvaluater[T](params.polyDegree),

		evaluationKey: evkey,
	}
}

// Decompose decomposes x with respect to decompParams.
// This function calculates t_i, where x = sum_{i=1}^level t_i * (Q / Base^i).
func (e Evaluater[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	mask := decompParams.base - 1
	baseLog := T(decompParams.baseLog)

	decomposed := make([]T, decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		res := x & mask
		x >>= baseLog
		carry := ((res - 1) | x) & res // WTF?
		carry >>= baseLog - 1
		x += carry
		res -= carry << baseLog
		decomposed[decompParams.level-i-1] = res
	}
	return decomposed
}

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	for i := 0; i < e.Parameters.lweDimension; i++ {
		ctOut.Mask[i] = ct0.Mask[i] + ct1.Mask[i]
	}
	*ctOut.Body = *ct0.Body + *ct1.Body
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
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluater.AddInPlace(ct0.Mask[i], ct1.Mask[i], ctOut.Mask[i])
	}
	e.polyEvaluater.AddInPlace(ct0.Body, ct1.Body, ctOut.Body)
}

// AddGLWEAssign adds GLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	e.AddGLWEInPlace(ct0, ctOut, ctOut)
}
