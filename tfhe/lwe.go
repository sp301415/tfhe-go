package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// LWESecretKey is a LWE secret key, sampled from uniform or block binary distribution.
type LWESecretKey[T TorusInt] struct {
	// Value has length DefaultLWEDimension.
	Value []T
}

// NewLWESecretKey allocates an empty LWESecretKey.
func NewLWESecretKey[T TorusInt](params Parameters[T]) LWESecretKey[T] {
	return LWESecretKey[T]{Value: make([]T, params.DefaultLWEDimension())}
}

// NewLWESecretKeyCustom allocates an empty LWESecretKey with given dimension.
func NewLWESecretKeyCustom[T TorusInt](lweDimension int) LWESecretKey[T] {
	return LWESecretKey[T]{Value: make([]T, lweDimension)}
}

// Copy returns a copy of the key.
func (sk LWESecretKey[T]) Copy() LWESecretKey[T] {
	return LWESecretKey[T]{Value: vec.Copy(sk.Value)}
}

// CopyFrom copies values from a key.
func (sk *LWESecretKey[T]) CopyFrom(skIn LWESecretKey[T]) {
	vec.CopyAssign(skIn.Value, sk.Value)
}

// Clear clears the key.
func (sk *LWESecretKey[T]) Clear() {
	vec.Fill(sk.Value, 0)
}

// LWEPublicKey is a LWE public key, derived from a secret key.
//
// We use compact public key, explained in https://eprint.iacr.org/2023/603.
// This means that not all parameters support public key encryption.
// Namely, DefaultLWEDimension should be power of two.
type LWEPublicKey[T TorusInt] struct {
	// Value has length 2,
	// and each polynomial has degree DefaultLWEDimension.
	Value []poly.Poly[T]
}

// NewLWEPublicKey allocates an empty LWEPublicKey.
//
// Panics if DefaultLWEDimension is not power of two.
func NewLWEPublicKey[T TorusInt](params Parameters[T]) LWEPublicKey[T] {
	return LWEPublicKey[T]{
		Value: []poly.Poly[T]{
			poly.NewPoly[T](params.DefaultLWEDimension()),
			poly.NewPoly[T](params.DefaultLWEDimension()),
		},
	}
}

// NewLWEPublicKeyCustom allocates an empty LWEPublicKey with given dimension.
//
// Panics if lweDimension is not power of two.
func NewLWEPublicKeyCustom[T TorusInt](lweDimension int) LWEPublicKey[T] {
	return LWEPublicKey[T]{
		Value: []poly.Poly[T]{
			poly.NewPoly[T](lweDimension),
			poly.NewPoly[T](lweDimension),
		},
	}
}

// Copy returns a copy of the key.
func (pk LWEPublicKey[T]) Copy() LWEPublicKey[T] {
	pkCopy := NewLWEPublicKeyCustom[T](pk.Value[0].Degree())
	pkCopy.Value[0].CopyFrom(pk.Value[0])
	pkCopy.Value[1].CopyFrom(pk.Value[1])
	return pkCopy
}

// CopyFrom copies values from a key.
func (pk *LWEPublicKey[T]) CopyFrom(pkIn LWEPublicKey[T]) {
	pk.Value[0].CopyFrom(pkIn.Value[0])
	pk.Value[1].CopyFrom(pkIn.Value[1])
}

// Clear clears the key.
func (pk *LWEPublicKey[T]) Clear() {
	pk.Value[0].Clear()
	pk.Value[1].Clear()
}

// LWEPlaintext represents an encoded LWE plaintext.
type LWEPlaintext[T TorusInt] struct {
	// Value is a scalar.
	Value T
}

// NewLWEPlaintext allocates an empty LWEPlaintext.
func NewLWEPlaintext[T TorusInt]() LWEPlaintext[T] {
	return LWEPlaintext[T]{}
}

// Copy returns a copy of the plaintext.
func (pt LWEPlaintext[T]) Copy() LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: pt.Value}
}

// CopyFrom copies values from a plaintext.
func (pt *LWEPlaintext[T]) CopyFrom(ptIn LWEPlaintext[T]) {
	pt.Value = ptIn.Value
}

// Clear clears the plaintext.
func (pt *LWEPlaintext[T]) Clear() {
	pt.Value = 0
}

// LWECiphertext represents an encrypted LWE ciphertext.
//
// LWE ciphertexts are the default encrypted form of the ciphertext.
type LWECiphertext[T TorusInt] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length DefaultLWEDimension + 1.
	Value []T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T TorusInt](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, params.DefaultLWEDimension()+1)}
}

// NewLWECiphertextCustom allocates an empty LWECiphertext with given dimension.
func NewLWECiphertextCustom[T TorusInt](lweDimension int) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, lweDimension+1)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{Value: vec.Copy(ct.Value)}
}

// CopyFrom copies values from a ciphertext.
func (ct *LWECiphertext[T]) CopyFrom(ctIn LWECiphertext[T]) {
	vec.CopyAssign(ctIn.Value, ct.Value)
}

// Clear clears the ciphertext.
func (ct *LWECiphertext[T]) Clear() {
	vec.Fill(ct.Value, 0)
}

// LevCiphertext is a leveled LWE ciphertext, decomposed according to GadgetParameters.
type LevCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []LWECiphertext[T]
}

// NewLevCiphertext allocates an empty LevCiphertext.
func NewLevCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ct := make([]LWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewLWECiphertext(params)
	}
	return LevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewLevCiphertextCustom allocates an empty LevCiphertext with given dimension.
func NewLevCiphertextCustom[T TorusInt](lweDimension int, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ct := make([]LWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewLWECiphertextCustom[T](lweDimension)
	}
	return LevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct LevCiphertext[T]) Copy() LevCiphertext[T] {
	ctCopy := make([]LWECiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return LevCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from a ciphertext.
func (ct *LevCiphertext[T]) CopyFrom(ctIn LevCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *LevCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}

// GSWCiphertext represents an encrypted GSW ciphertext,
// which is a DefaultLWEDimension+1 collection of Lev ciphertexts.
type GSWCiphertext[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length DefaultLWEDimension + 1.
	Value []LevCiphertext[T]
}

// NewGSWCiphertext allocates an empty GSW ciphertext.
func NewGSWCiphertext[T TorusInt](params Parameters[T], gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	lweDimension := params.DefaultLWEDimension()
	ct := make([]LevCiphertext[T], lweDimension+1)
	for i := 0; i < lweDimension+1; i++ {
		ct[i] = NewLevCiphertext(params, gadgetParams)
	}
	return GSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGSWCiphertextCustom allocates an empty GSW ciphertext with given dimension.
func NewGSWCiphertextCustom[T TorusInt](lweDimension int, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	ct := make([]LevCiphertext[T], lweDimension+1)
	for i := 0; i < lweDimension+1; i++ {
		ct[i] = NewLevCiphertextCustom[T](lweDimension, gadgetParams)
	}
	return GSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the ciphertext.
func (ct GSWCiphertext[T]) Copy() GSWCiphertext[T] {
	ctCopy := make([]LevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GSWCiphertext[T]{Value: ctCopy, GadgetParameters: ct.GadgetParameters}
}

// CopyFrom copies values from a ciphertext.
func (ct *GSWCiphertext[T]) CopyFrom(ctIn GSWCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.GadgetParameters = ctIn.GadgetParameters
}

// Clear clears the ciphertext.
func (ct *GSWCiphertext[T]) Clear() {
	for i := range ct.Value {
		ct.Value[i].Clear()
	}
}
