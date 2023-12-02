package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// LWEKey is a LWE secret key, sampled from uniform binary distribution.
type LWEKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []T
}

// NewLWEKey allocates an empty LWEKey.
func NewLWEKey[T Tint](params Parameters[T]) LWEKey[T] {
	return LWEKey[T]{Value: make([]T, params.lweDimension)}
}

// Copy returns a copy of the key.
func (sk LWEKey[T]) Copy() LWEKey[T] {
	return LWEKey[T]{Value: vec.Copy(sk.Value)}
}

// CopyFrom copies values from a key.
func (sk *LWEKey[T]) CopyFrom(skIn LWEKey[T]) {
	vec.CopyAssign(skIn.Value, sk.Value)
}

// Clear clears the key.
func (sk *LWEKey[T]) Clear() {
	vec.Fill(sk.Value, 0)
}

// LWEPlaintext represents an encoded LWE plaintext.
type LWEPlaintext[T Tint] struct {
	// Value is a scalar.
	Value T
}

// NewLWEPlaintext allocates an empty LWEPlaintext.
func NewLWEPlaintext[T Tint]() LWEPlaintext[T] {
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
type LWECiphertext[T Tint] struct {
	// Value is ordered as [body, mask],
	// since Go doesn't provide an easy way to take last element of slice.
	// Therefore, value has length LWEDimension + 1.
	Value []T
}

// NewLWECiphertext allocates an empty LWECiphertext.
func NewLWECiphertext[T Tint](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, params.lweDimension+1)}
}

// NewLWECiphertextCustom allocates an empty LWECiphertext with given dimension.
// Note that thre resulting ciphertext has length lweDimension + 1.
func NewLWECiphertextCustom[T Tint](lweDimension int) LWECiphertext[T] {
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
type LevCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length Level.
	Value []LWECiphertext[T]
}

// NewLevCiphertext allocates an empty LevCiphertext.
func NewLevCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ct := make([]LWECiphertext[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		ct[i] = NewLWECiphertext(params)
	}
	return LevCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewLevCiphertextCustom allocates an empty LevCiphertext with given dimension.
// Note that thre resulting ciphertext has length lweDimension + 1.
func NewLevCiphertextCustom[T Tint](lweDimension int, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
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
// which is a LWEDimension+1 collection of Lev ciphertexts.
type GSWCiphertext[T Tint] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length LWEDimension + 1.
	Value []LevCiphertext[T]
}

// NewGSWCiphertext allocates an empty GSW ciphertext.
func NewGSWCiphertext[T Tint](params Parameters[T], gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	ct := make([]LevCiphertext[T], params.lweDimension+1)
	for i := 0; i < params.lweDimension+1; i++ {
		ct[i] = NewLevCiphertext(params, gadgetParams)
	}
	return GSWCiphertext[T]{Value: ct, GadgetParameters: gadgetParams}
}

// NewGSWCiphertextCustom allocates an empty GSW ciphertext with given dimension.
// Note that thre resulting ciphertext has length lweDimension + 1.
func NewGSWCiphertextCustom[T Tint](lweDimension int, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
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
