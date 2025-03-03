package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// GLWETransformer is a struct for transforming
// GLWE entities to Fourier GLWE entities and vice versa.
// GLWETransformer is embedded in Encryptor and Evaluator,
// so usually manual instantiation isn't needed.
//
// GLWETransformer is not safe for concurrent use.
// Use [*GLWETransformer.ShallowCopy] to get a safe copy.
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

// ShallowCopy returns a shallow copy of this GLWETransformer.
// Returned GLWETransformer is safe for concurrent use.
func (e *GLWETransformer[T]) ShallowCopy() *GLWETransformer[T] {
	return &GLWETransformer[T]{
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),
	}
}

// ToFourierGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *GLWETransformer[T]) ToFourierGLWESecretKey(sk GLWESecretKey[T]) FourierGLWESecretKey[T] {
	skOut := NewFourierGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Degree())
	e.ToFourierGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToFourierGLWESecretKeyAssign transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToFourierGLWESecretKeyAssign(sk GLWESecretKey[T], skOut FourierGLWESecretKey[T]) {
	for i := 0; i < len(sk.Value); i++ {
		e.PolyEvaluator.ToFourierPolyAssign(sk.Value[i], skOut.Value[i])
	}
}

// ToGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *GLWETransformer[T]) ToGLWESecretKey(sk FourierGLWESecretKey[T]) GLWESecretKey[T] {
	skOut := NewGLWESecretKeyCustom[T](len(sk.Value), e.PolyEvaluator.Degree())
	e.ToGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToGLWESecretKeyAssign transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *GLWETransformer[T]) ToGLWESecretKeyAssign(sk FourierGLWESecretKey[T], skOut GLWESecretKey[T]) {
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

// ToFourierGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e *GLWETransformer[T]) ToFourierGLevCiphertext(ct GLevCiphertext[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToFourierGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLevCiphertextAssign transforms GLev ciphertext to Fourier GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierGLevCiphertextAssign(ct GLevCiphertext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ct.GadgetParameters.level; i++ {
		e.ToFourierGLWECiphertextAssign(ct.Value[i], ctOut.Value[i])
	}
}

// ToGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e *GLWETransformer[T]) ToGLevCiphertext(ct FourierGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertextCustom(len(ct.Value[0].Value)-1, e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGLevCiphertextAssign transforms Fourier GLev ciphertext to GLev ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToGLevCiphertextAssign(ct FourierGLevCiphertext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ct.GadgetParameters.level; i++ {
		e.ToGLWECiphertextAssign(ct.Value[i], ctOut.Value[i])
	}
}

// ToFourierGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e *GLWETransformer[T]) ToFourierGGSWCiphertext(ct GGSWCiphertext[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToFourierGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGGSWCiphertextAssign transforms GGSW ciphertext to Fourier GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToFourierGGSWCiphertextAssign(ct GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.ToFourierGLevCiphertextAssign(ct.Value[i], ctOut.Value[i])
	}
}

// ToGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e *GLWETransformer[T]) ToGGSWCiphertext(ct FourierGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertextCustom(len(ct.Value)-1, e.PolyEvaluator.Degree(), ct.GadgetParameters)
	e.ToGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGGSWCiphertextAssign transforms Fourier GGSW ciphertext to GGSW ciphertext and writes it to ctOut.
func (e *GLWETransformer[T]) ToGGSWCiphertextAssign(ct FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < len(ct.Value); i++ {
		e.ToGLevCiphertextAssign(ct.Value[i], ctOut.Value[i])
	}
}
