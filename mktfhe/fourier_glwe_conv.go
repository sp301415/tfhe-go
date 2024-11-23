package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWETransformer is a multi-key variant of [tfhe.GLWETransformer].
type GLWETransformer[T tfhe.TorusInt] struct {
	// Parameters is the parameters for this GLWETransformer.
	Parameters Parameters[T]

	// PolyEvaluator is a PolyEvaluator for this GLWETransformer.
	PolyEvaluator *poly.Evaluator[T]
}

// NewGLWETransformer allocates an empty GLWE transformer with given parameters.
func NewGLWETransformer[T tfhe.TorusInt](params Parameters[T]) *GLWETransformer[T] {
	return &GLWETransformer[T]{
		Parameters:    params,
		PolyEvaluator: poly.NewEvaluator[T](params.PolyDegree()),
	}
}

// ShallowCopy returns a shallow copy of this GLWE transformer.
// Returned GLWE transformer is safe for concurrent use.
func (e *GLWETransformer[T]) ShallowCopy() *GLWETransformer[T] {
	return &GLWETransformer[T]{
		Parameters:    e.Parameters,
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),
	}
}

// ToFourierGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *GLWETransformer[T]) ToFourierGLWESecretKey(sk tfhe.GLWESecretKey[T]) tfhe.FourierGLWESecretKey[T] {
	skOut := tfhe.NewFourierGLWESecretKeyCustom[T](e.Parameters.GLWERank(), e.Parameters.PolyDegree())
	e.ToFourierGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToFourierGLWESecretKeyAssign transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToFourierGLWESecretKeyAssign(skIn tfhe.GLWESecretKey[T], skOut tfhe.FourierGLWESecretKey[T]) {
	for i := 0; i < e.Parameters.singleKeyParameters.GLWERank(); i++ {
		e.PolyEvaluator.ToFourierPolyAssign(skIn.Value[i], skOut.Value[i])
	}
}

// ToGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) ToGLWESecretKey(sk tfhe.FourierGLWESecretKey[T]) tfhe.GLWESecretKey[T] {
	skOut := tfhe.NewGLWESecretKeyCustom[T](e.Parameters.singleKeyParameters.GLWERank(), e.Parameters.PolyDegree())
	e.ToGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToGLWESecretKeyAssign transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToGLWESecretKeyAssign(skIn tfhe.FourierGLWESecretKey[T], skOut tfhe.GLWESecretKey[T]) {
	for i := 0; i < e.Parameters.singleKeyParameters.GLWERank(); i++ {
		e.PolyEvaluator.ToPolyAssign(skIn.Value[i], skOut.Value[i])
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
		e.PolyEvaluator.ToFourierPolyAssign(ctIn.Value[i], ctOut.Value[i])
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
		e.PolyEvaluator.ToPolyAssign(ctIn.Value[i], ctOut.Value[i])
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
		e.PolyEvaluator.ToFourierPolyAssign(ctIn.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.PolyEvaluator.ToFourierPolyAssign(ctIn.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.PolyEvaluator.ToFourierPolyAssign(ctIn.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.PolyEvaluator.ToFourierPolyAssign(ctIn.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
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
		e.PolyEvaluator.ToPolyAssign(ctIn.Value[0].Value[j].Value[0], ctOut.Value[0].Value[j].Value[0])
		e.PolyEvaluator.ToPolyAssign(ctIn.Value[0].Value[j].Value[1], ctOut.Value[0].Value[j].Value[1])

		e.PolyEvaluator.ToPolyAssign(ctIn.Value[1].Value[j].Value[0], ctOut.Value[1].Value[j].Value[0])
		e.PolyEvaluator.ToPolyAssign(ctIn.Value[1].Value[j].Value[1], ctOut.Value[1].Value[j].Value[1])
	}
}
