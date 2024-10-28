package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVEvaluator evaluates BFV-type operations on RLWE ciphertexts.
// Only parameters with GLWERank = 1 are supported.
//
// BFVEvaluator is not safe for concurrent use.
// Use [*BFVEvaluator.ShallowCopy] to get a safe copy.
type BFVEvaluator[T tfhe.TorusInt] struct {
	// Parameters is the parameters for this BFVEvaluator.
	Parameters tfhe.Parameters[T]
	// BaseEvaluator is a base evaluator for this BFVEvaluator.
	// Note that it does not hold evaluaation keys, so bootstrapping is not supported.
	BaseEvaluator *tfhe.Evaluator[T]

	// KeySwitchKeys is the keyswitching keys for this BFVEvaluator.
	KeySwitchKeys BFVKeySwitchKey[T]

	buffer bfvEvaluationBuffer[T]
}

// bfvEvaluationBuffer is a buffer for BFV type evaluation.
type bfvEvaluationBuffer[T tfhe.TorusInt] struct {
	// ctFourier is the fourier transformed ciphertext for BFV multiplication.
	ctFourier [2]tfhe.FourierGLWECiphertext[T]
	// ctTensor is the tensored ciphertext for BFV multiplication.
	ctTensor [3]poly.Poly[T]
	// ctTensorFourier is the fourier transformed ctTensor.
	ctTensorFourier [3]poly.FourierPoly
	// ctPermute is the permuted ciphertext for BFV automorphism.
	ctPermute tfhe.GLWECiphertext[T]
	// ctPack is the permuted ciphertext for RingPack.
	ctPack tfhe.GLWECiphertext[T]
}

// NewBFVEvaluator creates a new BFVEvaluator.
//
// Panics when GLWERank > 1.
func NewBFVEvaluator[T tfhe.TorusInt](params tfhe.Parameters[T], keySwitchKeys BFVKeySwitchKey[T]) *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		Parameters:    params,
		BaseEvaluator: tfhe.NewEvaluator(params, tfhe.EvaluationKey[T]{}),
		KeySwitchKeys: keySwitchKeys,
		buffer:        newBFVEvaluationBuffer(params),
	}
}

// newBFVEvaluationBuffer creates a new BFVEvaluationBuffer.
func newBFVEvaluationBuffer[T tfhe.TorusInt](params tfhe.Parameters[T]) bfvEvaluationBuffer[T] {
	return bfvEvaluationBuffer[T]{
		ctFourier: [2]tfhe.FourierGLWECiphertext[T]{
			tfhe.NewFourierGLWECiphertext(params),
			tfhe.NewFourierGLWECiphertext(params),
		},
		ctTensor: [3]poly.Poly[T]{
			poly.NewPoly[T](params.PolyDegree()),
			poly.NewPoly[T](params.PolyDegree()),
			poly.NewPoly[T](params.PolyDegree()),
		},
		ctTensorFourier: [3]poly.FourierPoly{
			poly.NewFourierPoly(params.PolyDegree()),
			poly.NewFourierPoly(params.PolyDegree()),
			poly.NewFourierPoly(params.PolyDegree()),
		},
		ctPermute: tfhe.NewGLWECiphertext(params),
		ctPack:    tfhe.NewGLWECiphertext(params),
	}
}

// ShallowCopy creates a shallow copy of this BFVEvaluator.
func (e *BFVEvaluator[T]) ShallowCopy() *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		Parameters:    e.Parameters,
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		KeySwitchKeys: e.KeySwitchKeys,
		buffer:        newBFVEvaluationBuffer(e.Parameters),
	}
}

// Tensor computes the tensor product of two ciphertexts.
func (e *BFVEvaluator[T]) Tensor(ct0, ct1 tfhe.GLWECiphertext[T]) [3]poly.Poly[T] {
	ctOut := [3]poly.Poly[T]{
		e.BaseEvaluator.PolyEvaluator.NewPoly(),
		e.BaseEvaluator.PolyEvaluator.NewPoly(),
		e.BaseEvaluator.PolyEvaluator.NewPoly(),
	}
	e.TensorAssign(ct0, ct1, ctOut)
	return ctOut
}

// TensorAssign computes the tensor product of two ciphertexts and assigns the result to ctOut.
func (e *BFVEvaluator[T]) TensorAssign(ct0, ct1 tfhe.GLWECiphertext[T], ctOut [3]poly.Poly[T]) {
	e.BaseEvaluator.ToFourierGLWECiphertextAssign(ct0, e.buffer.ctFourier[0])
	e.BaseEvaluator.ToFourierGLWECiphertextAssign(ct1, e.buffer.ctFourier[1])

	e.BaseEvaluator.PolyEvaluator.FloatMulFourierPolyAssign(e.buffer.ctFourier[0].Value[0], 1/float64(e.Parameters.Scale()), e.buffer.ctFourier[0].Value[0])
	e.BaseEvaluator.PolyEvaluator.FloatMulFourierPolyAssign(e.buffer.ctFourier[0].Value[1], 1/float64(e.Parameters.Scale()), e.buffer.ctFourier[0].Value[1])

	e.BaseEvaluator.PolyEvaluator.MulFourierPolyAssign(e.buffer.ctFourier[0].Value[0], e.buffer.ctFourier[1].Value[0], e.buffer.ctTensorFourier[0])
	e.BaseEvaluator.PolyEvaluator.MulFourierPolyAssign(e.buffer.ctFourier[0].Value[0], e.buffer.ctFourier[1].Value[1], e.buffer.ctTensorFourier[1])
	e.BaseEvaluator.PolyEvaluator.MulAddFourierPolyAssign(e.buffer.ctFourier[0].Value[1], e.buffer.ctFourier[1].Value[0], e.buffer.ctTensorFourier[1])
	e.BaseEvaluator.PolyEvaluator.MulFourierPolyAssign(e.buffer.ctFourier[0].Value[1], e.buffer.ctFourier[1].Value[1], e.buffer.ctTensorFourier[2])

	e.BaseEvaluator.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctTensorFourier[0], ctOut[0])
	e.BaseEvaluator.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctTensorFourier[1], ctOut[1])
	e.BaseEvaluator.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctTensorFourier[2], ctOut[2])
}

// Relinearize relinearizes a tensor product of two ciphertexts.
func (e *BFVEvaluator[T]) Relinearize(ct [3]poly.Poly[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.RelinearizeAssign(ct, ctOut)
	return ctOut
}

// RelinearizeAssign relinearizes a tensor product of two ciphertexts and assigns the result to ctOut.
func (e *BFVEvaluator[T]) RelinearizeAssign(ct [3]poly.Poly[T], ctOut tfhe.GLWECiphertext[T]) {
	e.BaseEvaluator.GadgetProductGLWEAssign(e.KeySwitchKeys.RelinKey.Value[0], ct[2], ctOut)
	e.BaseEvaluator.PolyEvaluator.AddPolyAssign(ct[0], ctOut.Value[0], ctOut.Value[0])
	e.BaseEvaluator.PolyEvaluator.AddPolyAssign(ct[1], ctOut.Value[1], ctOut.Value[1])
}

// Mul returns ctOut = ct0 * ct1, using BFV multiplication.
func (e *BFVEvaluator[T]) Mul(ct0, ct1 tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.MulAssign(ct0, ct1, ctOut)
	return ctOut
}

// MulAssign assigns ctOut = ct0 * ct1, using BFV multiplication.
func (e *BFVEvaluator[T]) MulAssign(ct0, ct1 tfhe.GLWECiphertext[T], ctOut tfhe.GLWECiphertext[T]) {
	e.TensorAssign(ct0, ct1, e.buffer.ctTensor)
	e.RelinearizeAssign(e.buffer.ctTensor, ctOut)
}

// Permute returns ctOut = ct0(x^d), using BFV automorphism.
//
// Panics if BFVEvaluator does not have galois key for d.
func (e *BFVEvaluator[T]) Permute(ct0 tfhe.GLWECiphertext[T], d int) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.PermuteAssign(ct0, d, ctOut)
	return ctOut
}

// PermuteAssign assigns ctOut = ct0(x^d), using BFV automorphism.
//
// Panics if BFVEvaluator does not have galois key for d.
func (e *BFVEvaluator[T]) PermuteAssign(ct0 tfhe.GLWECiphertext[T], d int, ctOut tfhe.GLWECiphertext[T]) {
	e.BaseEvaluator.PermuteGLWEAssign(ct0, d, e.buffer.ctPermute)
	e.BaseEvaluator.GadgetProductGLWEAssign(e.KeySwitchKeys.GaloisKeys[d].Value[0], e.buffer.ctPermute.Value[1], ctOut)
	e.BaseEvaluator.PolyEvaluator.AddPolyAssign(e.buffer.ctPermute.Value[0], ctOut.Value[0], ctOut.Value[0])
}

// RingPack packs a LWE ciphertext to RLWE ciphertext.
func (e *BFVEvaluator[T]) RingPack(ct tfhe.LWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.RingPackAssign(ct, ctOut)
	return ctOut
}

// RingPackAssign packs a LWE ciphertext to RLWE ciphertext.
func (e *BFVEvaluator[T]) RingPackAssign(ct tfhe.LWECiphertext[T], ctOut tfhe.GLWECiphertext[T]) {
	ctOut.Value[0].Clear()
	ctOut.Value[0].Coeffs[0] = num.DivRoundBits(ct.Value[0], e.Parameters.LogPolyDegree())

	ctOut.Value[1].Coeffs[0] = ct.Value[1]
	for i := 1; i < e.Parameters.PolyDegree(); i++ {
		ctOut.Value[1].Coeffs[e.Parameters.PolyDegree()-i] = num.DivRoundBits(-ct.Value[i+1], e.Parameters.LogPolyDegree())
	}

	for i := 0; i < e.Parameters.LogPolyDegree(); i++ {
		e.PermuteAssign(ctOut, 1<<(e.Parameters.LogPolyDegree()-i)+1, e.buffer.ctPack)
		e.BaseEvaluator.AddGLWEAssign(ctOut, e.buffer.ctPack, ctOut)
	}
}
