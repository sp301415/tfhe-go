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

// ToFFTGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *GLWETransformer[T]) ToFFTGLWESecretKey(sk tfhe.GLWESecretKey[T]) tfhe.FFTGLWESecretKey[T] {
	skOut := tfhe.NewFFTGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.ToFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// ToFFTGLWESecretKeyTo transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToFFTGLWESecretKeyTo(skOut tfhe.FFTGLWESecretKey[T], sk tfhe.GLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.FFTTo(skOut.Value[i], sk.Value[i])
	}
}

// ToGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) ToGLWESecretKey(sk tfhe.FFTGLWESecretKey[T]) tfhe.GLWESecretKey[T] {
	skOut := tfhe.NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.ToGLWESecretKeyTo(skOut, sk)
	return skOut
}

// ToGLWESecretKeyTo transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToGLWESecretKeyTo(skOut tfhe.GLWESecretKey[T], sk tfhe.FFTGLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.InvFFTTo(skOut.Value[i], sk.Value[i])
	}
}

// ToFFTGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *GLWETransformer[T]) ToFFTGLWECiphertext(ct GLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.ToFFTGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// ToFFTGLWECiphertextTo transforms GLWE ciphertext to Fourier GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToFFTGLWECiphertextTo(ctOut FFTGLWECiphertext[T], ct GLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.FFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// ToGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) ToGLWECiphertext(ct FFTGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.ToGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// ToGLWECiphertextTo transforms Fourier GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToGLWECiphertextTo(ctOut GLWECiphertext[T], ct FFTGLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// ToFFTUniEncryption transforms UniEncryption to Fourier UniEncryption.
func (e *GLWETransformer[T]) ToFFTUniEncryption(ct UniEncryption[T]) FFTUniEncryption[T] {
	ctOut := NewFFTUniEncryptionCustom(e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.ToFFTUniEncryptionTo(ctOut, ct)
	return ctOut
}

// ToFFTUniEncryptionTo transforms UniEncryption to Fourier UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToFFTUniEncryptionTo(ctOut FFTUniEncryption[T], ct UniEncryption[T]) {
	for j := 0; j < ct.GadgetParams.Level(); j++ {
		e.PolyEvaluator.FFTTo(ctOut.Value[0].Value[j].Value[0], ct.Value[0].Value[j].Value[0])
		e.PolyEvaluator.FFTTo(ctOut.Value[0].Value[j].Value[1], ct.Value[0].Value[j].Value[1])

		e.PolyEvaluator.FFTTo(ctOut.Value[1].Value[j].Value[0], ct.Value[1].Value[j].Value[0])
		e.PolyEvaluator.FFTTo(ctOut.Value[1].Value[j].Value[1], ct.Value[1].Value[j].Value[1])
	}
}

// ToUniEncryption transforms Fourier UniEncryption to UniEncryption.
func (e *GLWETransformer[T]) ToUniEncryption(ct FFTUniEncryption[T]) UniEncryption[T] {
	ctOut := NewUniEncryptionCustom(e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.ToUniEncryptionTo(ctOut, ct)
	return ctOut
}

// ToUniEncryptionTo transforms Fourier UniEncryption to UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) ToUniEncryptionTo(ctOut UniEncryption[T], ct FFTUniEncryption[T]) {
	for j := 0; j < ct.GadgetParams.Level(); j++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[0].Value[j].Value[0], ct.Value[0].Value[j].Value[0])
		e.PolyEvaluator.InvFFTTo(ctOut.Value[0].Value[j].Value[1], ct.Value[0].Value[j].Value[1])

		e.PolyEvaluator.InvFFTTo(ctOut.Value[1].Value[j].Value[0], ct.Value[1].Value[j].Value[0])
		e.PolyEvaluator.InvFFTTo(ctOut.Value[1].Value[j].Value[1], ct.Value[1].Value[j].Value[1])
	}
}
