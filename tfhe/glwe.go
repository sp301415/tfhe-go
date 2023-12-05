package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GLWEKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWEKey[T Tint] struct {
	// Value has length GLWEDimension.
	Value []poly.Poly[T]
}

// NewGLWEKey allocates an empty GLWESecretKey.
func NewGLWEKey[T Tint](params Parameters[T]) GLWEKey[T] {
	sk := make([]poly.Poly[T], params.glweDimension)
	for i := range sk {
		sk[i] = poly.New[T](params.polyDegree)
	}
	return GLWEKey[T]{Value: sk}
}

// NewGLWEKeyCustom allocates an empty GLWESecretKey with given dimension and polyDegree.
func NewGLWEKeyCustom[T Tint](glweDimension, polyDegree int) GLWEKey[T] {
	sk := make([]poly.Poly[T], glweDimension)
	for i := range sk {
		sk[i] = poly.New[T](polyDegree)
	}
	return GLWEKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk GLWEKey[T]) Copy() GLWEKey[T] {
	skCopy := make([]poly.Poly[T], len(sk.Value))
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return GLWEKey[T]{Value: skCopy}
}

// CopyFrom copies values from a key.
func (sk *GLWEKey[T]) CopyFrom(skIn GLWEKey[T]) {
	for i := range sk.Value {
		sk.Value[i].CopyFrom(skIn.Value[i])
	}
}

// Clear clears the key.
func (sk *GLWEKey[T]) Clear() {
	for i := range sk.Value {
		sk.Value[i].Clear()
	}
}

// ToLWEKey returns a new LWE secret key derived from the GLWE secret key.
func (sk GLWEKey[T]) ToLWEKey() LWEKey[T] {
	glweDimension := len(sk.Value)
	degree := sk.Value[0].Degree()

	lweKey := LWEKey[T]{Value: make([]T, glweDimension*degree)}
	for i := 0; i < glweDimension; i++ {
		vec.CopyAssign(sk.Value[i].Coeffs, lweKey.Value[i*degree:(i+1)*degree])
	}
	return lweKey
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T Tint] struct {
	// Value is a single polynomial.
	Value poly.Poly[T]
}

// NewGLWEPlaintext allocates an empty GLWEPlaintext.
func NewGLWEPlaintext[T Tint](params Parameters[T]) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.New[T](params.polyDegree)}
}

// NewGLWEPlaintextCustom allocates an empty GLWEPlaintext with given polyDegree.
func NewGLWEPlaintextCustom[T Tint](polyDegree int) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.New[T](polyDegree)}
}

// Copy returns a copy of the plaintext.
func (pt GLWEPlaintext[T]) Copy() GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: pt.Value.Copy()}
}

// CopyFrom copies values from a plaintext.
func (pt *GLWEPlaintext[T]) CopyFrom(ptIn GLWEPlaintext[T]) {
	pt.Value.CopyFrom(ptIn.Value)
}

// Clear clears the plaintext.
func (pt *GLWEPlaintext[T]) Clear() {
	pt.Value.Clear()
}

// GLWECiphertext represents an encrypted GLWE ciphertext.
type GLWECiphertext[T Tint] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWEDimension + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T Tint](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = poly.New[T](params.polyDegree)
	}
	return GLWECiphertext[T]{Value: ct}
}

// NewGLWECiphertextCustom allocates an empty GLWECiphertext with given dimension and polyDegree.
func NewGLWECiphertextCustom[T Tint](glweDimension, polyDegree int) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], glweDimension+1)
	for i := 0; i < glweDimension+1; i++ {
		ct[i] = poly.New[T](polyDegree)
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

// Clear clears the ciphertext.
func (ct *GLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// GLevCiphertext is a leveled GLWE ciphertext, decomposed according to GadgetParameters.
type GLevCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []GLWECiphertext[T]
}

// NewGLevCiphertext allocates an empty GLevCiphertext.
func NewGLevCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewGLWECiphertext(params)
	}
	return GLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGLevCiphertextCustom allocates an empty GLevCiphertext with given dimension and polyDegree.
func NewGLevCiphertextCustom[T Tint](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewGLWECiphertextCustom[T](glweDimension, polyDegree)
	}
	return GLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct GLevCiphertext[T]) Copy() GLevCiphertext[T] {
	ctCopy := make([]GLWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GLevCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from ciphertext.
func (ct *GLevCiphertext[T]) CopyFrom(ctIn GLevCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *GLevCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// GGSWCiphertext represents an encrypted GGSW ciphertext,
// which is a GLWEDimension+1 collection of GLev ciphertexts.
type GGSWCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length GLWEDimension + 1.
	Value []GLevCiphertext[T]
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
func NewGGSWCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = NewGLevCiphertext(params, gadgetParams)
	}
	return GGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGGSWCiphertextCustom allocates an empty GGSW ciphertext with given dimension and polyDegree.
func NewGGSWCiphertextCustom[T Tint](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], glweDimension+1)
	for i := 0; i < glweDimension+1; i++ {
		ct[i] = NewGLevCiphertextCustom[T](glweDimension, polyDegree, gadgetParams)
	}
	return GGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct GGSWCiphertext[T]) Copy() GGSWCiphertext[T] {
	ctCopy := make([]GLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GGSWCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from a ciphertext.
func (ct *GGSWCiphertext[T]) CopyFrom(ctIn GGSWCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *GGSWCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
