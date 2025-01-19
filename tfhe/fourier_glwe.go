package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// FourierGLWESecretKey is a GLWE key in Fourier domain.
type FourierGLWESecretKey[T TorusInt] struct {
	// Value has length GLWERank.
	Value []poly.FourierPoly
}

// NewFourierGLWESecretKey creates a new FourierGLWESecretKey.
func NewFourierGLWESecretKey[T TorusInt](params Parameters[T]) FourierGLWESecretKey[T] {
	sk := make([]poly.FourierPoly, params.glweRank)
	for i := range sk {
		sk[i] = poly.NewFourierPoly(params.polyDegree)
	}
	return FourierGLWESecretKey[T]{Value: sk}
}

// NewFourierGLWESecretKeyCustom creates a new FourierGLWESecretKey with given dimension and polyDegree.
func NewFourierGLWESecretKeyCustom[T TorusInt](glweRank, polyDegree int) FourierGLWESecretKey[T] {
	sk := make([]poly.FourierPoly, glweRank)
	for i := range sk {
		sk[i] = poly.NewFourierPoly(polyDegree)
	}
	return FourierGLWESecretKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk FourierGLWESecretKey[T]) Copy() FourierGLWESecretKey[T] {
	skCopy := make([]poly.FourierPoly, len(sk.Value))
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return FourierGLWESecretKey[T]{Value: skCopy}
}

// CopyFrom copies values from the key.
func (sk *FourierGLWESecretKey[T]) CopyFrom(skIn FourierGLWESecretKey[T]) {
	for i := range sk.Value {
		sk.Value[i].CopyFrom(skIn.Value[i])
	}
}

// Clear clears the key.
func (sk *FourierGLWESecretKey[T]) Clear() {
	for i := range sk.Value {
		sk.Value[i].Clear()
	}
}

// FourierGLWECiphertext is a GLWE ciphertext in Fourier domain.
type FourierGLWECiphertext[T TorusInt] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWERank + 1.
	Value []poly.FourierPoly
}

// NewFourierGLWECiphertext creates a new FourierGLWECiphertext.
func NewFourierGLWECiphertext[T TorusInt](params Parameters[T]) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, params.glweRank+1)
	for i := range ct {
		ct[i] = poly.NewFourierPoly(params.polyDegree)
	}
	return FourierGLWECiphertext[T]{Value: ct}
}

// NewFourierGLWECiphertextCustom creates a new FourierGLWECiphertext with given dimension and polyDegree.
func NewFourierGLWECiphertextCustom[T TorusInt](glweRank, polyDegree int) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, glweRank+1)
	for i := range ct {
		ct[i] = poly.NewFourierPoly(polyDegree)
	}
	return FourierGLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLWECiphertext[T]) Copy() FourierGLWECiphertext[T] {
	ctCopy := make([]poly.FourierPoly, len(ct.Value))
	for i := range ctCopy {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGLWECiphertext[T]{Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *FourierGLWECiphertext[T]) CopyFrom(ctIn FourierGLWECiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// Clear clears the ciphertext.
func (ct *FourierGLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FourierGLevCiphertext is a leveled GLWE ciphertext in Fourier domain.
type FourierGLevCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []FourierGLWECiphertext[T]
}

// NewFourierGLevCiphertext creates a new FourierGLevCiphertext.
func NewFourierGLevCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := make([]FourierGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFourierGLWECiphertext(params)
	}
	return FourierGLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewFourierGLevCiphertextCustom creates a new FourierGLevCiphertext with given dimension and polyDegree.
func NewFourierGLevCiphertextCustom[T TorusInt](glweRank, polyDegree int, gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := make([]FourierGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFourierGLWECiphertextCustom[T](glweRank, polyDegree)
	}
	return FourierGLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLevCiphertext[T]) Copy() FourierGLevCiphertext[T] {
	ctCopy := make([]FourierGLWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGLevCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from the ciphertext.
func (ct *FourierGLevCiphertext[T]) CopyFrom(ctIn FourierGLevCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *FourierGLevCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FourierGGSWCiphertext represents an encrypted GGSW ciphertext in Fourier domain.
type FourierGGSWCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length GLWERank + 1.
	Value []FourierGLevCiphertext[T]
}

// NewFourierGGSWCiphertext creates a new GGSW ciphertext.
func NewFourierGGSWCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ct := make([]FourierGLevCiphertext[T], params.glweRank+1)
	for i := 0; i < params.glweRank+1; i++ {
		ct[i] = NewFourierGLevCiphertext(params, gadgetParams)
	}
	return FourierGGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewFourierGGSWCiphertextCustom creates a new GGSW ciphertext with given dimension and polyDegree.
func NewFourierGGSWCiphertextCustom[T TorusInt](glweRank, polyDegree int, gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ct := make([]FourierGLevCiphertext[T], glweRank+1)
	for i := 0; i < glweRank+1; i++ {
		ct[i] = NewFourierGLevCiphertextCustom(glweRank, polyDegree, gadgetParams)
	}
	return FourierGGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGGSWCiphertext[T]) Copy() FourierGGSWCiphertext[T] {
	ctCopy := make([]FourierGLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGGSWCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from the ciphertext.
func (ct *FourierGGSWCiphertext[T]) CopyFrom(ctIn FourierGGSWCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *FourierGGSWCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
