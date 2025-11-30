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

// SafeCopy returns a thread-safe copy.
func (e *GLWETransformer[T]) SafeCopy() *GLWETransformer[T] {
	return &GLWETransformer[T]{
		PolyEvaluator: e.PolyEvaluator.SafeCopy(),
	}
}

// FwdFFTGLWESecretKey transforms GLWE secret key to FFT GLWE secret key.
func (e *GLWETransformer[T]) FwdFFTGLWESecretKey(sk tfhe.GLWESecretKey[T]) tfhe.FFTGLWESecretKey[T] {
	skOut := tfhe.NewFFTGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.FwdFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// FwdFFTGLWESecretKeyTo transforms GLWE secret key to FFT GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) FwdFFTGLWESecretKeyTo(skOut tfhe.FFTGLWESecretKey[T], sk tfhe.GLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.FwdFFTPolyTo(skOut.Value[i], sk.Value[i])
	}
}

// InvFFTGLWESecretKey transforms FFT GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) InvFFTGLWESecretKey(sk tfhe.FFTGLWESecretKey[T]) tfhe.GLWESecretKey[T] {
	skOut := tfhe.NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.InvFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// InvFFTGLWESecretKeyTo transforms FFT GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) InvFFTGLWESecretKeyTo(skOut tfhe.GLWESecretKey[T], sk tfhe.FFTGLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.InvFFTTo(skOut.Value[i], sk.Value[i])
	}
}

// FwdFFTGLWECiphertext transforms GLWE ciphertext to FFT GLWE ciphertext.
func (e *GLWETransformer[T]) FwdFFTGLWECiphertext(ct GLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.FwdFFTGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// FwdFFTGLWECiphertextTo transforms GLWE ciphertext to FFT GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FwdFFTGLWECiphertextTo(ctOut FFTGLWECiphertext[T], ct GLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvGLWECiphertext transforms FFT GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) InvGLWECiphertext(ct FFTGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.InvGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// InvGLWECiphertextTo transforms FFT GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvGLWECiphertextTo(ctOut GLWECiphertext[T], ct FFTGLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// FwdFFTUniEncryption transforms UniEncryption to FFT UniEncryption.
func (e *GLWETransformer[T]) FwdFFTUniEncryption(ct UniEncryption[T]) FFTUniEncryption[T] {
	ctOut := NewFFTUniEncryptionCustom(e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.FwdFFTUniEncryptionTo(ctOut, ct)
	return ctOut
}

// FwdFFTUniEncryptionTo transforms UniEncryption to FFT UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) FwdFFTUniEncryptionTo(ctOut FFTUniEncryption[T], ct UniEncryption[T]) {
	for j := 0; j < ct.GadgetParams.Level(); j++ {
		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[0].Value[j].Value[0], ct.Value[0].Value[j].Value[0])
		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[0].Value[j].Value[1], ct.Value[0].Value[j].Value[1])

		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[1].Value[j].Value[0], ct.Value[1].Value[j].Value[0])
		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[1].Value[j].Value[1], ct.Value[1].Value[j].Value[1])
	}
}

// InvFFTUniEncryption transforms FFT UniEncryption to UniEncryption.
func (e *GLWETransformer[T]) InvFFTUniEncryption(ct FFTUniEncryption[T]) UniEncryption[T] {
	ctOut := NewUniEncryptionCustom(e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.InvFFTUniEncryptionTo(ctOut, ct)
	return ctOut
}

// InvFFTUniEncryptionTo transforms FFT UniEncryption to UniEncryption and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTUniEncryptionTo(ctOut UniEncryption[T], ct FFTUniEncryption[T]) {
	for j := 0; j < ct.GadgetParams.Level(); j++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[0].Value[j].Value[0], ct.Value[0].Value[j].Value[0])
		e.PolyEvaluator.InvFFTTo(ctOut.Value[0].Value[j].Value[1], ct.Value[0].Value[j].Value[1])

		e.PolyEvaluator.InvFFTTo(ctOut.Value[1].Value[j].Value[0], ct.Value[1].Value[j].Value[0])
		e.PolyEvaluator.InvFFTTo(ctOut.Value[1].Value[j].Value[1], ct.Value[1].Value[j].Value[1])
	}
}
