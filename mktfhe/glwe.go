package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWECiphertext is a Multi-Key GLWE ciphertext.
type GLWECiphertext[T tfhe.TorusInt] struct {
	// Value has length GLWEDimension + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext creates a new GLWE ciphertext.
func NewGLWECiphertext[T tfhe.TorusInt](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.GLWEDimension()+1)
	for i := 0; i < params.GLWEDimension()+1; i++ {
		ct[i] = poly.NewPoly[T](params.PolyDegree())
	}
	return GLWECiphertext[T]{Value: ct}
}

// NewGLWECiphertextCustom creates a new GLWE ciphertext with given (single-key) dimension, polyDegree and partyCount.
func NewGLWECiphertextCustom[T tfhe.TorusInt](partyCount, glweDimension, polyDegree int) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], partyCount*glweDimension+1)
	for i := 0; i < partyCount*glweDimension+1; i++ {
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

// CopyFrom copies values from a ciphertext.
func (ct *GLWECiphertext[T]) CopyFrom(ctIn GLWECiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
}

// CopyFromSingleKey copies values from a single-key ciphertext.
func (ct *GLWECiphertext[T]) CopyFromSingleKey(ctIn tfhe.GLWECiphertext[T], idx int) {
	if (len(ct.Value)-1)%(len(ctIn.Value)-1) != 0 {
		panic("GLWE Dimension mismatch")
	}

	singleGLWEDimension := len(ctIn.Value) - 1
	for i, ii := 0, idx*singleGLWEDimension; i < singleGLWEDimension; i, ii = i+1, ii+1 {
		ct.Value[1+ii].CopyFrom(ctIn.Value[1+i])
	}
	ct.Value[0].CopyFrom(ctIn.Value[0])
}

// Clear clears the ciphertext.
func (ct *GLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
