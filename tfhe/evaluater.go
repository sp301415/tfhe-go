package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

type EvaluationKey struct {
}

// Evaluater handles homomorphic operation of values.
// This is meant to be public.
type Evaluater[T Tint] struct {
	params Parameters[T]

	polyEvaluater poly.Evaluater[T]
}

// NewEvaluater creates a new Evaluater based on parameters.
func NewEvaluater[T Tint](params Parameters[T]) Evaluater[T] {
	return Evaluater[T]{
		params: params,

		polyEvaluater: poly.NewEvaluater[T](params.polyDegree),
	}
}

// checkLWEParams2 checks if ct0, ct1 aligns with evaluater's parameters, and panics if it doesn't.
func (e Evaluater[T]) checkLWEParams2(ct0, ct1 LWECiphertext[T]) {
	if ct0.Len() != e.params.lweDimension+1 || ct1.Len() != e.params.lweDimension+1 {
		panic("parameters mismatch")
	}
}

// checkLWEParams3 checks if ct0, ct1, ct2 aligns with evaluater's parameters, and panics if it doesn't.
func (e Evaluater[T]) checkLWEParams3(ct0, ct1, ct2 LWECiphertext[T]) {
	if ct0.Len() != e.params.lweDimension+1 || ct1.Len() != e.params.lweDimension+1 || ct2.Len() != e.params.lweDimension+1 {
		panic("parameters mismatch")
	}
}

// checkGLWEParams2 checks if ct0, ct1 aligns with evaluater's parameters, and panics if it doesn't.
func (e Evaluater[T]) checkGLWEParams2(ct0, ct1 GLWECiphertext[T]) {
	if ct0.Len() != e.params.glweDimension+1 || ct1.Len() != e.params.glweDimension+1 {
		panic("parameters mismatch")
	}
	for i := 0; i < e.params.glweDimension; i++ {
		if ct0.Mask[i].Degree() != e.params.polyDegree || ct1.Mask[i].Degree() != e.params.polyDegree {
			panic("parameters mismatch")
		}
	}
	if ct0.Body.Degree() != e.params.glweDimension || ct1.Body.Degree() != e.params.polyDegree {
		panic("parameters mismatch")
	}
}

// checkGLWEParams3 checks if ct0, ct1, ct2 aligns with evaluater's parameters, and panics if it doesn't.
func (e Evaluater[T]) checkGLWEParams3(ct0, ct1, ct2 GLWECiphertext[T]) {
	if ct0.Len() != e.params.glweDimension+1 || ct1.Len() != e.params.glweDimension+1 || ct2.Len() != e.params.glweDimension+1 {
		panic("parameters mismatch")
	}
	for i := 0; i < e.params.glweDimension; i++ {
		if ct0.Mask[i].Degree() != e.params.polyDegree || ct1.Mask[i].Degree() != e.params.polyDegree || ct2.Mask[i].Degree() != e.params.polyDegree {
			panic("parameters mismatch")
		}
	}
	if ct0.Body.Degree() != e.params.glweDimension || ct1.Body.Degree() != e.params.polyDegree || ct2.Body.Degree() != e.params.polyDegree {
		panic("parameters mismatch")
	}
}

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.params)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	e.checkLWEParams3(ct0, ct1, ctOut)

	for i := 0; i < e.params.lweDimension; i++ {
		ctOut.Mask[i] = ct0.Mask[i] + ct1.Mask[i]
	}
	ctOut.Body = ct0.Body + ct1.Body
}

// AddLWEAssign adds LWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddLWEAssign(ct0, ctOut LWECiphertext[T]) {
	e.AddLWEInPlace(ct0, ctOut, ctOut)
}

// AddGLWE adds two GLWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddGLWE(ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.params)
	e.AddGLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddGLWEInPlace adds two GLWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddGLWEInPlace(ct0, ct1, ctOut GLWECiphertext[T]) {
	e.checkGLWEParams3(ct0, ct1, ctOut)

	for i := 0; i < e.params.glweDimension; i++ {
		e.polyEvaluater.AddInPlace(ct0.Mask[i], ct1.Mask[i], ctOut.Mask[i])
	}
	e.polyEvaluater.AddInPlace(ct0.Body, ct1.Body, ctOut.Body)
}

// AddGLWEAssign adds GLWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddGLWEAssign(ct0, ctOut GLWECiphertext[T]) {
	e.AddGLWEInPlace(ct0, ctOut, ctOut)
}
