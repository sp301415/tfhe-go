package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FourierGLWECiphertext is a multi-key variant of [tfhe.FourierGLWECiphertext].
type FourierGLWECiphertext[T tfhe.TorusInt] struct {
	// Value has length GLWEDimension + 1.
	Value []poly.FourierPoly
}

// NewFourierGLWECiphertext allocates an empty Fourier GLWE ciphertext.
func NewFourierGLWECiphertext[T tfhe.TorusInt](params Parameters[T]) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, params.GLWEDimension()+1)
	for i := 0; i < params.GLWEDimension()+1; i++ {
		ct[i] = poly.NewFourierPoly(params.PolyDegree())
	}
	return FourierGLWECiphertext[T]{Value: ct}
}

// NewFourierGLWECiphertextCustom allocates an empty Fourier GLWE ciphertext with given polyDegree and partyCount.
func NewFourierGLWECiphertextCustom[T tfhe.TorusInt](partyCount, polyDegree int) FourierGLWECiphertext[T] {
	ct := make([]poly.FourierPoly, partyCount+1)
	for i := 0; i < partyCount+1; i++ {
		ct[i] = poly.NewFourierPoly(polyDegree)
	}
	return FourierGLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct FourierGLWECiphertext[T]) Copy() FourierGLWECiphertext[T] {
	ctCopy := make([]poly.FourierPoly, len(ct.Value))
	for i := range ct.Value {
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

// CopyFromSingleKey copies values from the single-key ciphertext.
//
// Panics if GLWEDimension of ctIn is not 1.
func (ct *FourierGLWECiphertext[T]) CopyFromSingleKey(ctIn tfhe.FourierGLWECiphertext[T], idx int) {
	if len(ctIn.Value) != 2 {
		panic("GLWEDimension of ctIn must be 1")
	}

	ct.Clear()
	ct.Value[0].CopyFrom(ctIn.Value[0])
	ct.Value[1+idx].CopyFrom(ctIn.Value[1])
}

// Clear clears the ciphertext.
func (ct *FourierGLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FourierUniEncryption is a multi-key variant of [tfhe.FourierGGSWCiphertext].
type FourierUniEncryption[T tfhe.TorusInt] struct {
	GadgetParameters tfhe.GadgetParameters[T]

	// Value has length 2, which equals to single-key GLWEDimension + 1.
	// The first element is always encrypted with the CRS as the mask.
	Value []tfhe.FourierGLevCiphertext[T]
}

// NewFourierUniEncryption allocates an empty Fourier UniEncryption.
func NewFourierUniEncryption[T tfhe.TorusInt](params Parameters[T], gadgetParams tfhe.GadgetParameters[T]) FourierUniEncryption[T] {
	return FourierUniEncryption[T]{
		GadgetParameters: gadgetParams,
		Value: []tfhe.FourierGLevCiphertext[T]{
			tfhe.NewFourierGLevCiphertextCustom(1, params.PolyDegree(), gadgetParams),
			tfhe.NewFourierGLevCiphertextCustom(1, params.PolyDegree(), gadgetParams),
		},
	}
}

// NewFourierUniEncryptionCustom allocates an empty FourierUniEncryption with given polyDegree and partyCount.
func NewFourierUniEncryptionCustom[T tfhe.TorusInt](polyDegree int, gadgetParams tfhe.GadgetParameters[T]) FourierUniEncryption[T] {
	return FourierUniEncryption[T]{
		GadgetParameters: gadgetParams,
		Value: []tfhe.FourierGLevCiphertext[T]{
			tfhe.NewFourierGLevCiphertextCustom(1, polyDegree, gadgetParams),
			tfhe.NewFourierGLevCiphertextCustom(1, polyDegree, gadgetParams),
		},
	}
}

// Copy returns a copy of the ciphertext.
func (ct FourierUniEncryption[T]) Copy() FourierUniEncryption[T] {
	ctCopy := make([]tfhe.FourierGLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FourierUniEncryption[T]{GadgetParameters: ct.GadgetParameters, Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *FourierUniEncryption[T]) CopyFrom(ctIn FourierUniEncryption[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// Clear clears the ciphertext.
func (ct *FourierUniEncryption[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
