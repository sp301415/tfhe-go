package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GLWESecretKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWESecretKey[T TorusInt] struct {
	// Value has length GLWEDimension.
	Value []poly.Poly[T]
}

// NewGLWESecretKey allocates an empty GLWESecretKey.
func NewGLWESecretKey[T TorusInt](params Parameters[T]) GLWESecretKey[T] {
	sk := make([]poly.Poly[T], params.glweDimension)
	for i := range sk {
		sk[i] = poly.NewPoly[T](params.polyDegree)
	}
	return GLWESecretKey[T]{Value: sk}
}

// NewGLWESecretKeyCustom allocates an empty GLWESecretKey with given dimension and polyDegree.
func NewGLWESecretKeyCustom[T TorusInt](glweDimension, polyDegree int) GLWESecretKey[T] {
	sk := make([]poly.Poly[T], glweDimension)
	for i := range sk {
		sk[i] = poly.NewPoly[T](polyDegree)
	}
	return GLWESecretKey[T]{Value: sk}
}

// Copy returns a copy of the key.
func (sk GLWESecretKey[T]) Copy() GLWESecretKey[T] {
	skCopy := make([]poly.Poly[T], len(sk.Value))
	for i := range skCopy {
		skCopy[i] = sk.Value[i].Copy()
	}
	return GLWESecretKey[T]{Value: skCopy}
}

// CopyFrom copies values from a key.
func (sk *GLWESecretKey[T]) CopyFrom(skIn GLWESecretKey[T]) {
	for i := range sk.Value {
		sk.Value[i].CopyFrom(skIn.Value[i])
	}
}

// Clear clears the key.
func (sk *GLWESecretKey[T]) Clear() {
	for i := range sk.Value {
		sk.Value[i].Clear()
	}
}

// GLWEPublicKey is a GLWE public key, derived from the GLWE secret key.
type GLWEPublicKey[T TorusInt] struct {
	// Value has length GLWEDimension.
	Value []GLWECiphertext[T]
}

// NewGLWEPublicKey allocates an empty GLWEPublicKey.
func NewGLWEPublicKey[T TorusInt](params Parameters[T]) GLWEPublicKey[T] {
	pk := make([]GLWECiphertext[T], params.glweDimension)
	for i := range pk {
		pk[i] = NewGLWECiphertext(params)
	}
	return GLWEPublicKey[T]{Value: pk}
}

// NewGLWEPublicKeyCustom allocates an empty GLWEPublicKey with given dimension and polyDegree.
func NewGLWEPublicKeyCustom[T TorusInt](glweDimension, polyDegree int) GLWEPublicKey[T] {
	pk := make([]GLWECiphertext[T], glweDimension)
	for i := range pk {
		pk[i] = NewGLWECiphertextCustom[T](glweDimension, polyDegree)
	}
	return GLWEPublicKey[T]{Value: pk}
}

// Copy returns a copy of the key.
func (pk GLWEPublicKey[T]) Copy() GLWEPublicKey[T] {
	pkCopy := make([]GLWECiphertext[T], len(pk.Value))
	for i := range pkCopy {
		pkCopy[i] = pk.Value[i].Copy()
	}
	return GLWEPublicKey[T]{Value: pkCopy}
}

// CopyFrom copies values from a key.
func (pk *GLWEPublicKey[T]) CopyFrom(pkIn GLWEPublicKey[T]) {
	for i := range pk.Value {
		pk.Value[i].CopyFrom(pkIn.Value[i])
	}
}

// Clear clears the key.
func (pk *GLWEPublicKey[T]) Clear() {
	for i := range pk.Value {
		pk.Value[i].Clear()
	}
}

// ToLWEKey derives a new LWE secret key from the GLWE secret key.
// Returned LWEKey will be of dimension LWELargeDimension.
func (sk GLWESecretKey[T]) ToLWEKey() LWESecretKey[T] {
	lweKey := NewLWESecretKeyCustom[T](len(sk.Value) * sk.Value[0].Degree())
	sk.ToLWEKeyAssign(lweKey)
	return lweKey
}

// ToLWEKeyAssign derives a new LWE secret key from the GLWE secret key and writes it to skOut.
// skOut should have dimension LWELargeDimension.
func (sk GLWESecretKey[T]) ToLWEKeyAssign(skOut LWESecretKey[T]) {
	glweDimension := len(sk.Value)
	degree := sk.Value[0].Degree()

	for i := 0; i < glweDimension; i++ {
		vec.CopyAssign(sk.Value[i].Coeffs, skOut.Value[i*degree:(i+1)*degree])
	}
}

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T TorusInt] struct {
	// Value is a single polynomial.
	Value poly.Poly[T]
}

// NewGLWEPlaintext allocates an empty GLWEPlaintext.
func NewGLWEPlaintext[T TorusInt](params Parameters[T]) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.NewPoly[T](params.polyDegree)}
}

// NewGLWEPlaintextCustom allocates an empty GLWEPlaintext with given polyDegree.
func NewGLWEPlaintextCustom[T TorusInt](polyDegree int) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.NewPoly[T](polyDegree)}
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
type GLWECiphertext[T TorusInt] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length GLWEDimension + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext allocates an empty GLWECiphertext.
func NewGLWECiphertext[T TorusInt](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = poly.NewPoly[T](params.polyDegree)
	}
	return GLWECiphertext[T]{Value: ct}
}

// NewGLWECiphertextCustom allocates an empty GLWECiphertext with given dimension and polyDegree.
func NewGLWECiphertextCustom[T TorusInt](glweDimension, polyDegree int) GLWECiphertext[T] {
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

// ToLWECiphertext extracts LWE ciphertext of given index from GLWE ciphertext.
// The output ciphertext will be of dimension LWELargeDimension + 1,
// encrypted with LWELargeKey.
//
// Equivalent to Evaluator.SampleExtract.
func (ct GLWECiphertext[T]) ToLWECiphertext(idx int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T]((len(ct.Value) - 1) * ct.Value[0].Degree())
	ct.ToLWECiphertextAssign(idx, ctOut)
	return ctOut
}

// ToLWECiphertextAssign extracts LWE ciphertext of given index from GLWE ciphertext and writes it to ctOut.
// The output ciphertext should be of dimension LWELargeDimension + 1,
// and it will be a ciphertext encrypted with LWELargeKey.
//
// Equivalent to Evaluator.SampleExtractAssign.
func (ct GLWECiphertext[T]) ToLWECiphertextAssign(idx int, ctOut LWECiphertext[T]) {
	glweDimension := len(ct.Value) - 1
	degree := ct.Value[0].Degree()

	ctOut.Value[0] = ct.Value[0].Coeffs[idx]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < glweDimension; i++ {
		start := i * degree
		end := (i + 1) * degree

		vec.ReverseAssign(ctMask[i].Coeffs, ctOutMask[start:end])

		vec.RotateInPlace(ctOutMask[start:end], idx+1)
		vec.NegAssign(ctOutMask[start+idx+1:end], ctOutMask[start+idx+1:end])
	}
}

// GLevCiphertext is a leveled GLWE ciphertext, decomposed according to GadgetParameters.
type GLevCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []GLWECiphertext[T]
}

// NewGLevCiphertext allocates an empty GLevCiphertext.
func NewGLevCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewGLWECiphertext(params)
	}
	return GLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGLevCiphertextCustom allocates an empty GLevCiphertext with given dimension and polyDegree.
func NewGLevCiphertextCustom[T TorusInt](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
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
type GGSWCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length GLWEDimension + 1.
	Value []GLevCiphertext[T]
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
func NewGGSWCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = NewGLevCiphertext(params, gadgetParams)
	}
	return GGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGGSWCiphertextCustom allocates an empty GGSW ciphertext with given dimension and polyDegree.
func NewGGSWCiphertextCustom[T TorusInt](glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
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
