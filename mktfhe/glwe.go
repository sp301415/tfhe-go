package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWECiphertext is a multi-key variant of [tfhe.GLWECiphertext].
// Due to the structure of UniEncryption,
// all multi-key GLWE ciphertexts are actually RLWE ciphertexts.
type GLWECiphertext[T tfhe.TorusInt] struct {
	// Value has length GLWEDimension + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWE ciphertext.
func NewGLWECiphertext[T tfhe.TorusInt](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.GLWEDimension()+1)
	for i := 0; i < params.GLWEDimension()+1; i++ {
		ct[i] = poly.NewPoly[T](params.PolyDegree())
	}
	return GLWECiphertext[T]{Value: ct}
}

// NewGLWECiphertextCustom allocates an empty GLWE ciphertext with given dimension and partyCount.
func NewGLWECiphertextCustom[T tfhe.TorusInt](glweDimension, polyDegree int) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], glweDimension+1)
	for i := 0; i < glweDimension+1; i++ {
		ct[i] = poly.NewPoly[T](polyDegree)
	}
	return GLWECiphertext[T]{Value: ct}
}

// Copy returns a copy of the ciphertext.
func (ct GLWECiphertext[T]) Copy() GLWECiphertext[T] {
	ctCopy := make([]poly.Poly[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GLWECiphertext[T]{Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *GLWECiphertext[T]) CopyFrom(ctIn GLWECiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// CopyFromSingleKey copies values from the single-key ciphertext.
//
// Panics if GLWEDimension of ctIn is not 1.
func (ct *GLWECiphertext[T]) CopyFromSingleKey(ctIn tfhe.GLWECiphertext[T], idx int) {
	if len(ctIn.Value) != 2 {
		panic("GLWEDimension of ctIn must be 1")
	}

	ct.Clear()
	ct.Value[0].CopyFrom(ctIn.Value[0])
	ct.Value[1+idx].CopyFrom(ctIn.Value[1])
}

// Clear clears the ciphertext.
func (ct *GLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// UniEncryption is a multi-key variant of [tfhe.GGSWCiphertext].
type UniEncryption[T tfhe.TorusInt] struct {
	GadgetParameters tfhe.GadgetParameters[T]

	// Value has length 2, which equals to single-key GLWEDimension + 1.
	// The first element is always encrypted with the CRS as the mask.
	Value []tfhe.GLevCiphertext[T]
}

// NewUniEncryption allocates an empty UniEncryption.
func NewUniEncryption[T tfhe.TorusInt](params Parameters[T], gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	return UniEncryption[T]{
		GadgetParameters: gadgetParams,
		Value: []tfhe.GLevCiphertext[T]{
			tfhe.NewGLevCiphertextCustom(1, params.PolyDegree(), gadgetParams),
			tfhe.NewGLevCiphertextCustom(1, params.PolyDegree(), gadgetParams),
		},
	}
}

// NewUniEncryptionCustom allocates an empty UniEncryption with given polyDegree and partyCount.
func NewUniEncryptionCustom[T tfhe.TorusInt](polyDegree int, gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	return UniEncryption[T]{
		GadgetParameters: gadgetParams,
		Value: []tfhe.GLevCiphertext[T]{
			tfhe.NewGLevCiphertextCustom(1, polyDegree, gadgetParams),
			tfhe.NewGLevCiphertextCustom(1, polyDegree, gadgetParams),
		},
	}
}

// Copy returns a copy of the ciphertext.
func (ct UniEncryption[T]) Copy() UniEncryption[T] {
	ctCopy := make([]tfhe.GLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return UniEncryption[T]{GadgetParameters: ct.GadgetParameters, Value: ctCopy}
}

// CopyFrom copies values from the ciphertext.
func (ct *UniEncryption[T]) CopyFrom(ctIn UniEncryption[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// Clear clears the ciphertext.
func (ct *UniEncryption[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
