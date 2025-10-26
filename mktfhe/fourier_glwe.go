package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FFTGLWECiphertext is a multi-key variant of [tfhe.FFTGLWECiphertext].
type FFTGLWECiphertext[T tfhe.TorusInt] struct {
	// Value has length GLWERank + 1.
	Value []poly.FFTPoly
}

// NewFFTGLWECiphertext creates a new Fourier GLWE ciphertext.
func NewFFTGLWECiphertext[T tfhe.TorusInt](params Parameters[T]) FFTGLWECiphertext[T] {
	ct := make([]poly.FFTPoly, params.GLWERank()+1)
	for i := 0; i < params.GLWERank()+1; i++ {
		ct[i] = poly.NewFFTPoly(params.PolyRank())
	}
	return FFTGLWECiphertext[T]{Value: ct}
}

// NewFFTGLWECiphertextCustom creates a new Fourier GLWE ciphertext with given dimension and polyRank
func NewFFTGLWECiphertextCustom[T tfhe.TorusInt](glweRank, polyRank int) FFTGLWECiphertext[T] {
	ct := make([]poly.FFTPoly, glweRank+1)
	for i := 0; i < glweRank+1; i++ {
		ct[i] = poly.NewFFTPoly(polyRank)
	}
	return FFTGLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct FFTGLWECiphertext[T]) Copy() FFTGLWECiphertext[T] {
	ctCopy := make([]poly.FFTPoly, len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FFTGLWECiphertext[T]{Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *FFTGLWECiphertext[T]) CopyFrom(ctIn FFTGLWECiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// CopyFromSubKey copies values from the single-key ciphertext.
//
// Panics if GLWERank of ctIn is not 1.
func (ct *FFTGLWECiphertext[T]) CopyFromSubKey(ctIn tfhe.FFTGLWECiphertext[T], idx int) {
	if len(ctIn.Value) != 2 {
		panic("GLWERank of ctIn must be 1")
	}

	ct.Clear()
	ct.Value[0].CopyFrom(ctIn.Value[0])
	ct.Value[1+idx].CopyFrom(ctIn.Value[1])
}

// Clear clears the ciphertext.
func (ct *FFTGLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// FFTUniEncryption is a multi-key variant of [tfhe.FFTGGSWCiphertext].
type FFTUniEncryption[T tfhe.TorusInt] struct {
	GadgetParams tfhe.GadgetParameters[T]

	// Value has length 2, which equals to single-key GLWERank + 1.
	// The first element is always encrypted with the CRS as the mask.
	Value []tfhe.FFTGLevCiphertext[T]
}

// NewFFTUniEncryption creates a new Fourier UniEncryption.
func NewFFTUniEncryption[T tfhe.TorusInt](params Parameters[T], gadgetParams tfhe.GadgetParameters[T]) FFTUniEncryption[T] {
	return FFTUniEncryption[T]{
		GadgetParams: gadgetParams,
		Value: []tfhe.FFTGLevCiphertext[T]{
			tfhe.NewFFTGLevCiphertextCustom(1, params.PolyRank(), gadgetParams),
			tfhe.NewFFTGLevCiphertextCustom(1, params.PolyRank(), gadgetParams),
		},
	}
}

// NewFFTUniEncryptionCustom creates a new FFTUniEncryption with given polyRank and partyCount.
func NewFFTUniEncryptionCustom[T tfhe.TorusInt](polyRank int, gadgetParams tfhe.GadgetParameters[T]) FFTUniEncryption[T] {
	return FFTUniEncryption[T]{
		GadgetParams: gadgetParams,
		Value: []tfhe.FFTGLevCiphertext[T]{
			tfhe.NewFFTGLevCiphertextCustom(1, polyRank, gadgetParams),
			tfhe.NewFFTGLevCiphertextCustom(1, polyRank, gadgetParams),
		},
	}
}

// Copy returns a copy of the ciphertext.
func (ct FFTUniEncryption[T]) Copy() FFTUniEncryption[T] {
	ctCopy := make([]tfhe.FFTGLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return FFTUniEncryption[T]{GadgetParams: ct.GadgetParams, Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *FFTUniEncryption[T]) CopyFrom(ctIn FFTUniEncryption[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// Clear clears the ciphertext.
func (ct *FFTUniEncryption[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
