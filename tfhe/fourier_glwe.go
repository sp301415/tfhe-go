package tfhe

import "github.com/sp301415/tfhe-go/math/poly"

// FourierGLWECiphertext is a GLWE ciphertext in Fourier domain.
type FourierGLWECiphertext[T Tint] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWEDimension + 1.
	Value []poly.FourierPoly
}

// NewFourierGLWECiphertext allocates an empty FourierGLWECiphertext.
func NewFourierGLWECiphertext[T Tint](params Parameters[T]) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, params.glweDimension+1)
	for i := range ct {
		ct[i] = poly.NewFourierPoly(params.polyDegree)
	}
	return FourierGLWECiphertext[T]{Value: ct}
}

// NewFourierGLWECiphertextCustom allocates an empty FourierGLWECiphertext with given dimension and polyDegree.
// Note that the resulting ciphertext has length glweDimension + 1.
func NewFourierGLWECiphertextCustom[T Tint](glweDimension, polyDegree int) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, glweDimension+1)
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

// CopyFrom copies values from a ciphertext.
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
type FourierGLevCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []FourierGLWECiphertext[T]
}

// NewFourierGLevCiphertext allocates an empty FourierGLevCiphertext.
func NewFourierGLevCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := make([]FourierGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFourierGLWECiphertext(params)
	}
	return FourierGLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewFourierGLevCiphertextCustom allocates an empty FourierGLevCiphertext with given dimension and polyDegree.
// Note that each GLWE ciphertext has length glweDimension + 1.
func NewFourierGLevCiphertextCustom[T Tint](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := make([]FourierGLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewFourierGLWECiphertextCustom[T](glweDimension, polyDegree)
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

// CopyFrom copies values from a ciphertext.
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
type FourierGGSWCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length GLWEDimension + 1.
	Value []FourierGLevCiphertext[T]
}

// NewFourierGGSWCiphertext allocates an empty GGSW ciphertext.
func NewFourierGGSWCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ct := make([]FourierGLevCiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = NewFourierGLevCiphertext(params, gadgetParams)
	}
	return FourierGGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewFourierGGSWCiphertextCustom allocates an empty GGSW ciphertext with given dimension and polyDegree.
// Note that each GLWE ciphertext has length glweDimension + 1.
func NewFourierGGSWCiphertextCustom[T Tint](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ct := make([]FourierGLevCiphertext[T], glweDimension+1)
	for i := 0; i < glweDimension+1; i++ {
		ct[i] = NewFourierGLevCiphertextCustom[T](glweDimension, polyDegree, gadgetParams)
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

// CopyFrom copies values from a ciphertext.
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
