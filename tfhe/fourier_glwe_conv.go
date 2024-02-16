package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// glweTransformer is a internal type for
// transforming GLWE entities to Fourier GLWE entities and vice versa.
type glweTransformer[T TorusInt] struct {
	// Compact Parameters
	glweDimension int
	polyDegree    int

	FourierEvaluator *poly.FourierEvaluator[T]
}

// newGLWETransformer returns a new glweTransformer with given parameters.
func newGLWETransformer[T TorusInt](params Parameters[T]) *glweTransformer[T] {
	return &glweTransformer[T]{
		glweDimension:    params.glweDimension,
		polyDegree:       params.polyDegree,
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),
	}
}

// ShallowCopy returns a shallow copy of this glweTransformer.
// Returned glweTransformer is safe for concurrent use.
func (e *glweTransformer[T]) ShallowCopy() *glweTransformer[T] {
	return &glweTransformer[T]{
		glweDimension:    e.glweDimension,
		polyDegree:       e.polyDegree,
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),
	}
}

// ToFourierGLWESecretKey transforms GLWE secret key to Fourier GLWE secret key.
func (e *glweTransformer[T]) ToFourierGLWESecretKey(sk GLWESecretKey[T]) FourierGLWESecretKey[T] {
	skOut := NewFourierGLWESecretKeyCustom[T](e.glweDimension, e.polyDegree)
	e.ToFourierGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToFourierGLWESecretKeyAssign transforms GLWE secret key to Fourier GLWE secret key and writes it to skOut.
func (e *glweTransformer[T]) ToFourierGLWESecretKeyAssign(skIn GLWESecretKey[T], skOut FourierGLWESecretKey[T]) {
	for i := 0; i < e.glweDimension; i++ {
		e.FourierEvaluator.ToFourierPolyAssign(skIn.Value[i], skOut.Value[i])
	}
}

// ToGLWESecretKey transforms Fourier GLWE secret key to GLWE secret key.
func (e *glweTransformer[T]) ToGLWESecretKey(sk FourierGLWESecretKey[T]) GLWESecretKey[T] {
	skOut := NewGLWESecretKeyCustom[T](e.glweDimension, e.polyDegree)
	e.ToGLWESecretKeyAssign(sk, skOut)
	return skOut
}

// ToGLWESecretKeyAssign transforms Fourier GLWE secret key to GLWE secret key and writes it to skOut.
func (e *glweTransformer[T]) ToGLWESecretKeyAssign(skIn FourierGLWESecretKey[T], skOut GLWESecretKey[T]) {
	for i := 0; i < e.glweDimension; i++ {
		e.FourierEvaluator.ToPolyAssign(skIn.Value[i], skOut.Value[i])
	}
}

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *glweTransformer[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertextCustom[T](e.glweDimension, e.polyDegree)
	e.ToFourierGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextAssign transforms GLWE ciphertext to Fourier GLWE ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToFourierGLWECiphertextAssign(ctIn GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledFourierPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *glweTransformer[T]) ToGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertextCustom[T](e.glweDimension, e.polyDegree)
	e.ToGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGLWECiphertextAssign transforms Fourier GLWE ciphertext to GLWE ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToGLWECiphertextAssign(ctIn FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e *glweTransformer[T]) ToFourierGLevCiphertext(ct GLevCiphertext[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertextCustom(e.glweDimension, e.polyDegree, ct.GadgetParameters)
	e.ToFourierGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLevCiphertextAssign transforms GLev ciphertext to Fourier GLev ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToFourierGLevCiphertextAssign(ctIn GLevCiphertext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToFourierGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e *glweTransformer[T]) ToGLevCiphertext(ct FourierGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertextCustom[T](e.glweDimension, e.polyDegree, ct.GadgetParameters)
	e.ToGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGLevCiphertextAssign transforms Fourier GLev ciphertext to GLev ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToGLevCiphertextAssign(ctIn FourierGLevCiphertext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e *glweTransformer[T]) ToFourierGGSWCiphertext(ct GGSWCiphertext[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertextCustom[T](e.glweDimension, e.polyDegree, ct.GadgetParameters)
	e.ToFourierGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGGSWCiphertextAssign transforms GGSW ciphertext to Fourier GGSW ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToFourierGGSWCiphertextAssign(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.glweDimension+1; i++ {
		e.ToFourierGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e *glweTransformer[T]) ToGGSWCiphertext(ct FourierGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertextCustom[T](e.glweDimension, e.polyDegree, ct.GadgetParameters)
	e.ToGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToGGSWCiphertextAssign transforms Fourier GGSW ciphertext to GGSW ciphertext and writes it to ctOut.
func (e *glweTransformer[T]) ToGGSWCiphertextAssign(ctIn FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < e.glweDimension+1; i++ {
		e.ToGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}
