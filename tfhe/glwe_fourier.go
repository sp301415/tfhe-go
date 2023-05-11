package tfhe

import "github.com/sp301415/tfhe/math/poly"

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

// Copy returns a copy of the ciphertext.
func (ct FourierGLWECiphertext[T]) Copy() FourierGLWECiphertext[T] {
	ctCopy := make([]poly.FourierPoly, len(ct.Value))
	for i := range ctCopy {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGLWECiphertext[T]{Value: ctCopy}
}

// FourierGLevCiphertext is a leveled GLWE ciphertext in Fourier domain.
type FourierGLevCiphertext[T Tint] struct {
	// Value has length Level.
	Value []FourierGLWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewFourierGLevCiphertext allocates an empty FourierGLevCiphertext.
func NewFourierGLevCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) FourierGLevCiphertext[T] {
	ct := make([]FourierGLWECiphertext[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		ct[i] = NewFourierGLWECiphertext(params)
	}
	return FourierGLevCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLevCiphertext[T]) Copy() FourierGLevCiphertext[T] {
	ctCopy := make([]FourierGLWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGLevCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct FourierGLevCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}

// GGSWCiphertext represents an encrypted GGSW ciphertext in Fourier domain.
type FourierGGSWCiphertext[T Tint] struct {
	// Value has length GLWEDimension + 1.
	Value []FourierGLevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewFourierGGSWCiphertext allocates an empty GGSW ciphertext.
func NewFourierGGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	ct := make([]FourierGLevCiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = NewFourierGLevCiphertext(params, decompParams)
	}
	return FourierGGSWCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGGSWCiphertext[T]) Copy() FourierGGSWCiphertext[T] {
	ctCopy := make([]FourierGLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierGGSWCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct FourierGGSWCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
