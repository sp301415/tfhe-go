package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// LWECiphertext is a multi-key variant of [tfhe.LWECiphertext].
type LWECiphertext[T tfhe.TorusInt] struct {
	// Value has length DefaultDimension + 1.
	Value []T
}

// NewLWECiphertext creates a new LWE ciphertext.
func NewLWECiphertext[T tfhe.TorusInt](params Parameters[T]) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, params.DefaultLWEDimension()+1)}
}

// NewLWECiphertextCustom creates a new LWE ciphertext with given dimension.
func NewLWECiphertextCustom[T tfhe.TorusInt](lweDimension int) LWECiphertext[T] {
	return LWECiphertext[T]{Value: make([]T, lweDimension+1)}
}

// Copy returns a copy of the ciphertext.
func (ct LWECiphertext[T]) Copy() LWECiphertext[T] {
	return LWECiphertext[T]{Value: vec.Copy(ct.Value)}
}

// CopyFrom copies values from the ciphertext.
func (ct *LWECiphertext[T]) CopyFrom(ctIn LWECiphertext[T]) {
	vec.CopyAssign(ctIn.Value, ct.Value)
}

// CopyFromSingleKey copies values from the single-key ciphertext.
//
// Panics if the dimension of the ciphertext is not a multiple of the dimension of the single-key ciphertext.
func (ct *LWECiphertext[T]) CopyFromSingleKey(ctIn tfhe.LWECiphertext[T], idx int) {
	if (len(ct.Value)-1)%(len(ctIn.Value)-1) != 0 {
		panic("LWE Dimension mismatch")
	}

	ct.Clear()
	singleKeyLWEDimension := len(ctIn.Value) - 1
	vec.CopyAssign(ctIn.Value[1:], ct.Value[1+idx*singleKeyLWEDimension:1+(idx+1)*singleKeyLWEDimension])
	ct.Value[0] = ctIn.Value[0]
}

// Clear clears the ciphertext.
func (ct *LWECiphertext[T]) Clear() {
	vec.Fill(ct.Value, 0)
}
