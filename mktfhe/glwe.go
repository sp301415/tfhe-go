package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GLWECiphertext is a Multi-Key GLWE ciphertext.
// Due to the structure of UniEncryption,
// all multi-key GLWE ciphertexts are actually RLWE ciphertexts.
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

// NewGLWECiphertextCustom creates a new GLWE ciphertext with given polyDegree and partyCount.
func NewGLWECiphertextCustom[T tfhe.TorusInt](partyCount, polyDegree int) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], partyCount+1)
	for i := 0; i < partyCount+1; i++ {
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
