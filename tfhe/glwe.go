package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GLWESecretKey is a GLWE secret key, sampled from uniform binary distribution.
type GLWESecretKey[T TorusInt] struct {
	// Value has length GLWERank.
	Value []poly.Poly[T]
}

// NewGLWESecretKey creates a new GLWESecretKey.
func NewGLWESecretKey[T TorusInt](params Parameters[T]) GLWESecretKey[T] {
	sk := make([]poly.Poly[T], params.glweRank)
	for i := range sk {
		sk[i] = poly.NewPoly[T](params.polyDegree)
	}
	return GLWESecretKey[T]{Value: sk}
}

// NewGLWESecretKeyCustom creates a new GLWESecretKey with given dimension and polyDegree.
func NewGLWESecretKeyCustom[T TorusInt](glweRank, polyDegree int) GLWESecretKey[T] {
	sk := make([]poly.Poly[T], glweRank)
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

// CopyFrom copies values from the key.
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

// ToLWEKey derives a new LWE secret key from the GLWE secret key.
// Returned LWEKey will be of length GLWEDimension.
func (sk GLWESecretKey[T]) ToLWEKey() LWESecretKey[T] {
	lweKey := NewLWESecretKeyCustom[T](len(sk.Value) * sk.Value[0].Degree())
	sk.ToLWEKeyAssign(lweKey)
	return lweKey
}

// ToLWEKeyAssign derives a new LWE secret key from the GLWE secret key and writes it to skOut.
// skOut should have dimension GLWEDimension.
func (sk GLWESecretKey[T]) ToLWEKeyAssign(skOut LWESecretKey[T]) {
	glweRank := len(sk.Value)
	degree := sk.Value[0].Degree()

	for i := 0; i < glweRank; i++ {
		vec.CopyAssign(sk.Value[i].Coeffs, skOut.Value[i*degree:(i+1)*degree])
	}
}

// GLWEPublicKey is a GLWE public key, derived from the GLWE secret key.
type GLWEPublicKey[T TorusInt] struct {
	// Value has length GLWERank.
	Value []GLWECiphertext[T]
}

// NewGLWEPublicKey creates a new GLWEPublicKey.
func NewGLWEPublicKey[T TorusInt](params Parameters[T]) GLWEPublicKey[T] {
	pk := make([]GLWECiphertext[T], params.glweRank)
	for i := 0; i < params.glweRank; i++ {
		pk[i] = NewGLWECiphertext(params)
	}
	return GLWEPublicKey[T]{Value: pk}
}

// NewGLWEPublicKeyCustom creates a new GLWEPublicKey with given dimension and polyDegree.
func NewGLWEPublicKeyCustom[T TorusInt](glweRank, polyDegree int) GLWEPublicKey[T] {
	pk := make([]GLWECiphertext[T], glweRank)
	for i := 0; i < glweRank; i++ {
		pk[i] = NewGLWECiphertextCustom[T](glweRank, polyDegree)
	}
	return GLWEPublicKey[T]{Value: pk}
}

// Copy returns a copy of the key.
func (pk GLWEPublicKey[T]) Copy() GLWEPublicKey[T] {
	pkCopy := make([]GLWECiphertext[T], len(pk.Value))
	for i := range pk.Value {
		pkCopy[i] = pk.Value[i].Copy()
	}
	return GLWEPublicKey[T]{Value: pkCopy}
}

// CopyFrom copies values from the key.
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

// GLWEPlaintext represents an encoded GLWE plaintext.
type GLWEPlaintext[T TorusInt] struct {
	// Value is a single polynomial.
	Value poly.Poly[T]
}

// NewGLWEPlaintext creates a new GLWEPlaintext.
func NewGLWEPlaintext[T TorusInt](params Parameters[T]) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.NewPoly[T](params.polyDegree)}
}

// NewGLWEPlaintextCustom creates a new GLWEPlaintext with given polyDegree.
func NewGLWEPlaintextCustom[T TorusInt](polyDegree int) GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: poly.NewPoly[T](polyDegree)}
}

// Copy returns a copy of the plaintext.
func (pt GLWEPlaintext[T]) Copy() GLWEPlaintext[T] {
	return GLWEPlaintext[T]{Value: pt.Value.Copy()}
}

// CopyFrom copies values from the plaintext.
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
	// Therefore, value has length GLWERank + 1.
	Value []poly.Poly[T]
}

// NewGLWECiphertext creates a new GLWECiphertext.
func NewGLWECiphertext[T TorusInt](params Parameters[T]) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], params.glweRank+1)
	for i := 0; i < params.glweRank+1; i++ {
		ct[i] = poly.NewPoly[T](params.polyDegree)
	}
	return GLWECiphertext[T]{Value: ct}
}

// NewGLWECiphertextCustom creates a new GLWECiphertext with given dimension and polyDegree.
func NewGLWECiphertextCustom[T TorusInt](glweRank, polyDegree int) GLWECiphertext[T] {
	ct := make([]poly.Poly[T], glweRank+1)
	for i := 0; i < glweRank+1; i++ {
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

// Clear clears the ciphertext.
func (ct *GLWECiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// ToLWECiphertext extracts LWE ciphertext of given index from GLWE ciphertext.
// The output ciphertext will be of length GLWEDimension + 1,
// encrypted with LWELargeKey.
func (ct GLWECiphertext[T]) ToLWECiphertext(idx int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T]((len(ct.Value) - 1) * ct.Value[0].Degree())
	ct.ToLWECiphertextAssign(idx, ctOut)
	return ctOut
}

// ToLWECiphertextAssign extracts LWE ciphertext of given index from GLWE ciphertext and writes it to ctOut.
// The output ciphertext should be of length GLWEDimension + 1,
// and it will be a ciphertext encrypted with LWELargeKey.
func (ct GLWECiphertext[T]) ToLWECiphertextAssign(idx int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[idx]

	for i := 0; i < len(ct.Value)-1; i++ {
		for j := 0; j <= idx; j++ {
			ctOut.Value[1+i*ct.Value[i+1].Degree()+j] = ct.Value[i+1].Coeffs[idx-j]
		}
		for j := idx + 1; j < ct.Value[i+1].Degree(); j++ {
			ctOut.Value[1+i*ct.Value[i+1].Degree()+j] = -ct.Value[i+1].Coeffs[idx-j+ct.Value[i+1].Degree()]
		}
	}
}

// GLevCiphertext is a leveled GLWE ciphertext, decomposed according to GadgetParameters.
type GLevCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []GLWECiphertext[T]
}

// NewGLevCiphertext creates a new GLevCiphertext.
func NewGLevCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewGLWECiphertext(params)
	}
	return GLevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGLevCiphertextCustom creates a new GLevCiphertext with given dimension and polyDegree.
func NewGLevCiphertextCustom[T TorusInt](glweRank, polyDegree int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := make([]GLWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewGLWECiphertextCustom[T](glweRank, polyDegree)
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
// which is a GLWERank+1 collection of GLev ciphertexts.
type GGSWCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length GLWERank + 1.
	Value []GLevCiphertext[T]
}

// NewGGSWCiphertext creates a new GGSW ciphertext.
func NewGGSWCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], params.glweRank+1)
	for i := 0; i < params.glweRank+1; i++ {
		ct[i] = NewGLevCiphertext(params, gadgetParams)
	}
	return GGSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGGSWCiphertextCustom creates a new GGSW ciphertext with given dimension and polyDegree.
func NewGGSWCiphertextCustom[T TorusInt](glweRank, polyDegree int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], glweRank+1)
	for i := 0; i < glweRank+1; i++ {
		ct[i] = NewGLevCiphertextCustom(glweRank, polyDegree, gadgetParams)
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

// CopyFrom copies values from the ciphertext.
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
