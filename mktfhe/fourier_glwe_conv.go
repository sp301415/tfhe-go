package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWETransformer is a multi-key variant of [tfhe.GLWETransformer].
type GLWETransformer[T tfhe.TorusInt] struct {
	// PolyEvaluator is a PolyEvaluator for this GLWETransformer.
	PolyEvaluator *poly.Evaluator[T]
}

// NewGLWETransformer creates a new GLWE transformer with given parameters.
func NewGLWETransformer[T tfhe.TorusInt](N int) *GLWETransformer[T] {
	return &GLWETransformer[T]{
		PolyEvaluator: poly.NewEvaluator[T](N),
	}
}

// ShallowCopy returns a shallow copy of this GLWE transformer.
// Returned GLWE transformer is safe for concurrent use.
func (e *GLWETransformer[T]) ShallowCopy() *GLWETransformer[T] {
	return &GLWETransformer[T]{
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),
	}
}

// ToFourierGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *GLWETransformer[T]) ToFourierGLWESecretKey(sk tfhe.GLWESecretKey[T]) tfhe.FourierGLWESecretKey[T] {
	skOut := tfhe.NewFourierGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Degree())
	e.ToFourierGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToFourierGLWESecretKeyAssign transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToFourierGLWESecretKeyAssign(sk tfhe.GLWESecretKey[T], skOut tfhe.FourierGLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.ToFourierPolyAssign(sk.Value[i], skOut.Value[i])
	}
}

// ToGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) ToGLWESecretKey(sk tfhe.FourierGLWESecretKey[T]) tfhe.GLWESecretKey[T] {
	skOut := tfhe.NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Degree())
	e.ToGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToGLWESecretKeyAssign transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToGLWESecretKeyAssign(sk tfhe.FourierGLWESecretKey[T], skOut tfhe.GLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.ToPolyAssign(sk.Value[i], skOut.Value[i])
	}
}

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *GLWETransformer[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Degree())
	e.ToFourierGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextAssign transforms GLWE ciphertext to Fourier GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierGLWECiphertextAssign(ct GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.ToFourierPolyAssign(ct.Value[i], ctOut.Value[i])
	}
}

// ToGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) ToGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Degree())
	e.ToGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGLWECiphertextAssign transforms Fourier GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToGLWECiphertextAssign(ct FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.ToPolyAssign(ct.Value[i], ctOut.Value[i])
	}
}

// ToFourierUniEncryption transforms UniEncryption to Fourier UniEncryption.
func (e *GLWETransformer[T]) ToFourierUniEncryption(ct UniEncryption[T]) FourierUniEncryption[T] {
	ctOut := NewFourierUniEncryptionCustom(e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToFourierUniEncryptionAssign(ct, ctOut)
	return ctOut
}

// ToFourierUniEncryptionAssign transforms UniEncryption to Fourier UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierUniEncryptionAssign(ct UniEncryption[T], ctOut FourierUniEncryption[T]) {
	for j := 0; j < ct.GadgetParameters.Level(); j++ {
		e.PolyEvaluator.ToFourierPolyAssign(ct.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.PolyEvaluator.ToFourierPolyAssign(ct.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.PolyEvaluator.ToFourierPolyAssign(ct.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.PolyEvaluator.ToFourierPolyAssign(ct.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
	}
}

// ToUniEncryption transforms Fourier UniEncryption to UniEncryption.
func (e *GLWETransformer[T]) ToUniEncryption(ct FourierUniEncryption[T]) UniEncryption[T] {
	ctOut := NewUniEncryptionCustom(e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToUniEncryptionAssign(ct, ctOut)
	return ctOut
}

// ToUniEncryptionAssign transforms Fourier UniEncryption to UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToUniEncryptionAssign(ct FourierUniEncryption[T], ctOut UniEncryption[T]) {
	for j := 0; j < ct.GadgetParameters.Level(); j++ {
		e.PolyEvaluator.ToPolyAssign(ct.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.PolyEvaluator.ToPolyAssign(ct.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.PolyEvaluator.ToPolyAssign(ct.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.PolyEvaluator.ToPolyAssign(ct.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
	}
}
