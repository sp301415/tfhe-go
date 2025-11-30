package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// GLWETransformer is a struct for transforming
// GLWE entities to FFT GLWE entities and vice versa.
// GLWETransformer is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
//
// GLWETransformer is not safe for concurrent use.
// Use [*GLWETransformer.SafeCopy] to get a safe copy.
type GLWETransformer[T TorusInt] struct {
	// PolyEvaluator is a PolyEvaluator for this GLWETransformer.
	PolyEvaluator *poly.Evaluator[T]
}

// NewGLWETransformer returns a new GLWETransformer with given parameters.
func NewGLWETransformer[T TorusInt](N int) *GLWETransformer[T] {
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
func (e *GLWETransformer[T]) FwdFFTGLWESecretKey(sk GLWESecretKey[T]) FFTGLWESecretKey[T] {
	skOut := NewFFTGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.FwdFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// FwdFFTGLWESecretKeyTo transforms GLWE secret key to FFT GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) FwdFFTGLWESecretKeyTo(skOut FFTGLWESecretKey[T], sk GLWESecretKey[T]) {
	for i := 0; i < len(skOut.Value); i++ {
		e.PolyEvaluator.FwdFFTPolyTo(skOut.Value[i], sk.Value[i])
	}
}

// InvFFTGLWESecretKey transforms FFT GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) InvFFTGLWESecretKey(sk FFTGLWESecretKey[T]) GLWESecretKey[T] {
	skOut := NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.InvFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// InvFFTGLWESecretKeyTo transforms FFT GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) InvFFTGLWESecretKeyTo(skOut GLWESecretKey[T], sk FFTGLWESecretKey[T]) {
	for i := 0; i < len(skOut.Value); i++ {
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
	for i := 0; i < len(ctOut.Value); i++ {
		e.PolyEvaluator.FwdFFTPolyTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGLWECiphertext transforms FFT GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) InvFFTGLWECiphertext(ct FFTGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.InvFFTGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGLWECiphertextTo transforms FFT GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGLWECiphertextTo(ctOut GLWECiphertext[T], ct FFTGLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// FwdFFTGLevCiphertext transforms GLev ciphertext to FFT GLev ciphertext.
func (e *GLWETransformer[T]) FwdFFTGLevCiphertext(ct GLevCiphertext[T]) FFTGLevCiphertext[T] {
	ctOut := NewFFTGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.FwdFFTGLevCiphertextTo(ctOut, ct)
	return ctOut
}

// FwdFFTGLevCiphertextTo transforms GLev ciphertext to FFT GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FwdFFTGLevCiphertextTo(ctOut FFTGLevCiphertext[T], ct GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.FwdFFTGLWECiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGLevCiphertext transforms FFT GLev ciphertext to GLev ciphertext.
func (e *GLWETransformer[T]) InvFFTGLevCiphertext(ct FFTGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.InvFFTGLevCiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGLevCiphertextTo transforms FFT GLev ciphertext to GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGLevCiphertextTo(ctOut GLevCiphertext[T], ct FFTGLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.InvFFTGLWECiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// FwdFFTGGSWCiphertext transforms GGSW ciphertext to FFT GGSW ciphertext.
func (e *GLWETransformer[T]) FwdFFTGGSWCiphertext(ct GGSWCiphertext[T]) FFTGGSWCiphertext[T] {
	ctOut := NewFFTGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.FwdFFTGGSWCiphertextTo(ctOut, ct)
	return ctOut
}

// FwdFFTGGSWCiphertextTo transforms GGSW ciphertext to FFT GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FwdFFTGGSWCiphertextTo(ctOut FFTGGSWCiphertext[T], ct GGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.FwdFFTGLevCiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGGSWCiphertext transforms FFT GGSW ciphertext to GGSW ciphertext.
func (e *GLWETransformer[T]) InvFFTGGSWCiphertext(ct FFTGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.InvFFTGGSWCiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGGSWCiphertextTo transforms FFT GGSW ciphertext to GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGGSWCiphertextTo(ctOut GGSWCiphertext[T], ct FFTGGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.InvFFTGLevCiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}
