package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// GLWETransformer is a struct for transforming
// GLWE entities to Fourier GLWE entities and vice versa.
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

// FFTGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *GLWETransformer[T]) FFTGLWESecretKey(sk GLWESecretKey[T]) FFTGLWESecretKey[T] {
	skOut := NewFFTGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.FFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// FFTGLWESecretKeyTo transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) FFTGLWESecretKeyTo(skOut FFTGLWESecretKey[T], sk GLWESecretKey[T]) {
	for i := 0; i < len(skOut.Value); i++ {
		e.PolyEvaluator.FFTTo(skOut.Value[i], sk.Value[i])
	}
}

// InvFFTGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) InvFFTGLWESecretKey(sk FFTGLWESecretKey[T]) GLWESecretKey[T] {
	skOut := NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Rank())
	e.InvFFTGLWESecretKeyTo(skOut, sk)
	return skOut
}

// InvFFTGLWESecretKeyTo transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) InvFFTGLWESecretKeyTo(skOut GLWESecretKey[T], sk FFTGLWESecretKey[T]) {
	for i := 0; i < len(skOut.Value); i++ {
		e.PolyEvaluator.InvFFTTo(skOut.Value[i], sk.Value[i])
	}
}

// FFTGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *GLWETransformer[T]) FFTGLWECiphertext(ct GLWECiphertext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.FFTGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// FFTGLWECiphertextTo transforms GLWE ciphertext to Fourier GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FFTGLWECiphertextTo(ctOut FFTGLWECiphertext[T], ct GLWECiphertext[T]) {
	for i := 0; i < len(ctOut.Value); i++ {
		e.PolyEvaluator.FFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *GLWETransformer[T]) InvFFTGLWECiphertext(ct FFTGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](len(ct.Value)-1, e.PolyEvaluator.Rank())
	e.InvFFTGLWECiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGLWECiphertextTo transforms Fourier GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGLWECiphertextTo(ctOut GLWECiphertext[T], ct FFTGLWECiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.PolyEvaluator.InvFFTTo(ctOut.Value[i], ct.Value[i])
	}
}

// FFTGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e *GLWETransformer[T]) FFTGLevCiphertext(ct GLevCiphertext[T]) FFTGLevCiphertext[T] {
	ctOut := NewFFTGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.FFTGLevCiphertextTo(ctOut, ct)
	return ctOut
}

// FFTGLevCiphertextTo transforms GLev ciphertext to Fourier GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FFTGLevCiphertextTo(ctOut FFTGLevCiphertext[T], ct GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.FFTGLWECiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e *GLWETransformer[T]) InvFFTGLevCiphertext(ct FFTGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.InvFFTGLevCiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGLevCiphertextTo transforms Fourier GLev ciphertext to GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGLevCiphertextTo(ctOut GLevCiphertext[T], ct FFTGLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.InvFFTGLWECiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// FFTGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e *GLWETransformer[T]) FFTGGSWCiphertext(ct GGSWCiphertext[T]) FFTGGSWCiphertext[T] {
	ctOut := NewFFTGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.FFTGGSWCiphertextTo(ctOut, ct)
	return ctOut
}

// FFTGGSWCiphertextTo transforms GGSW ciphertext to Fourier GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) FFTGGSWCiphertextTo(ctOut FFTGGSWCiphertext[T], ct GGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.FFTGLevCiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}

// InvFFTGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e *GLWETransformer[T]) InvFFTGGSWCiphertext(ct FFTGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Rank(), ct.GadgetParams)
	e.InvFFTGGSWCiphertextTo(ctOut, ct)
	return ctOut
}

// InvFFTGGSWCiphertextTo transforms Fourier GGSW ciphertext to GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) InvFFTGGSWCiphertextTo(ctOut GGSWCiphertext[T], ct FFTGGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.InvFFTGLevCiphertextTo(ctOut.Value[i], ct.Value[i])
	}
}
