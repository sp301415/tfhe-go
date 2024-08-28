package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWETransformer is a multi-key variant of [tfhe.GLWETransformer].
type GLWETransformer[T tfhe.TorusInt] struct {
	// Parameters holds parameters for this GLWETransformer.
	Parameters Parameters[T]

	// FourierEvaluator is a FourierEvaluator for this GLWETransformer.
	FourierEvaluator *poly.FourierEvaluator[T]
}

// NewGLWETransformer allocates an empty GLWE transformer with given parameters.
func NewGLWETransformer[T tfhe.TorusInt](params Parameters[T]) *GLWETransformer[T] {
	return &GLWETransformer[T]{
		Parameters:       params,
		FourierEvaluator: poly.NewFourierEvaluator[T](params.PolyDegree()),
	}
}

// ShallowCopy returns a shallow copy of this GLWE transformer.
// Returned GLWE transformer is safe for concurrent use.
func (e *GLWETransformer[T]) ShallowCopy() *GLWETransformer[T] {
	return &GLWETransformer[T]{
		Parameters:       e.Parameters,
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),
	}
}

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *GLWETransformer[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertextCustom[T](e.Parameters.GLWERank(), e.Parameters.PolyDegree())
	e.ToFourierGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextAssign transforms GLWE ciphertext to Fourier GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierGLWECiphertextAssign(ctIn GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.FourierEvaluator.ToFourierPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) ToGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](e.Parameters.GLWERank(), e.Parameters.PolyDegree())
	e.ToGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGLWECiphertextAssign transforms Fourier GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToGLWECiphertextAssign(ctIn FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.FourierEvaluator.ToPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierUniEncryption transforms UniEncryption to Fourier UniEncryption.
func (e *GLWETransformer[T]) ToFourierUniEncryption(ct UniEncryption[T]) FourierUniEncryption[T] {
	ctOut := NewFourierUniEncryptionCustom(e.Parameters.PolyDegree(), ct.GadgetParameters)
	e.ToFourierUniEncryptionAssign(ct, ctOut)
	return ctOut
}

// ToFourierUniEncryptionAssign transforms UniEncryption to Fourier UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierUniEncryptionAssign(ctIn UniEncryption[T], ctOut FourierUniEncryption[T]) {
	for j := 0; j < ctIn.GadgetParameters.Level(); j++ {
		e.FourierEvaluator.ToFourierPolyAssign(ctIn.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.FourierEvaluator.ToFourierPolyAssign(ctIn.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.FourierEvaluator.ToFourierPolyAssign(ctIn.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.FourierEvaluator.ToFourierPolyAssign(ctIn.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
	}
}

// ToUniEncryption transforms Fourier UniEncryption to UniEncryption.
func (e *GLWETransformer[T]) ToUniEncryption(ct FourierUniEncryption[T]) UniEncryption[T] {
	ctOut := NewUniEncryptionCustom(e.Parameters.PolyDegree(), ct.GadgetParameters)
	e.ToUniEncryptionAssign(ct, ctOut)
	return ctOut
}

// ToUniEncryptionAssign transforms Fourier UniEncryption to UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToUniEncryptionAssign(ctIn FourierUniEncryption[T], ctOut UniEncryption[T]) {
	for j := 0; j < ctIn.GadgetParameters.Level(); j++ {
		e.FourierEvaluator.ToPolyAssign(ctIn.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.FourierEvaluator.ToPolyAssign(ctIn.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.FourierEvaluator.ToPolyAssign(ctIn.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.FourierEvaluator.ToPolyAssign(ctIn.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
	}
}
