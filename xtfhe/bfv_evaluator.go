package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVEvaluator evaluates BFV-type operations on GLWE ciphertexts.
//
// BFVEvaluator is not safe for concurrent use.
// Use [*BFVEvaluator.ShallowCopy] to get a safe copy.
type BFVEvaluator[T tfhe.TorusInt] struct {
	// BaseEvaluator is a base evaluator for this BFVEvaluator.
	// Note that it does not hold evaluaation keys, so bootstrapping is not supported.
	BaseEvaluator *tfhe.Evaluator[T]
	// PolyEvaluator is a PolyEvaluator for this BFVEvaluator.
	PolyEvaluator *poly.Evaluator[T]

	// Parameters is the parameters for this BFVEvaluator.
	Parameters tfhe.Parameters[T]

	// EvaluationKey is the keyswitching keys for this BFVEvaluator.
	EvaluationKey BFVEvaluationKey[T]

	buffer bfvEvaluationBuffer[T]
}

// bfvEvaluationBuffer is a buffer for BFV type evaluation.
type bfvEvaluationBuffer[T tfhe.TorusInt] struct {
	// ctFourier is the fourier transformed ciphertext for BFV multiplication.
	ctMulFourier [2]tfhe.FourierGLWECiphertext[T]
	// ctTensor is the tensored ciphertext for BFV multiplication.
	ctTensor tfhe.GLWECiphertext[T]
	// ctTensorFourier is the fourier transformed ctTensor.
	ctTensorFourier tfhe.FourierGLWECiphertext[T]
	// ctPermute is the permuted ciphertext for BFV automorphism.
	ctPermute tfhe.GLWECiphertext[T]
	// ctPack is the permuted ciphertext for RingPack.
	ctPack tfhe.GLWECiphertext[T]
}

// NewBFVEvaluator creates a new BFVEvaluator.
func NewBFVEvaluator[T tfhe.TorusInt](params tfhe.Parameters[T], evk BFVEvaluationKey[T]) *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		BaseEvaluator: tfhe.NewEvaluator(params, tfhe.EvaluationKey[T]{}),
		PolyEvaluator: poly.NewEvaluator[T](params.PolyDegree()),
		Parameters:    params,
		EvaluationKey: evk,
		buffer:        newBFVEvaluationBuffer(params),
	}
}

// newBFVEvaluationBuffer creates a new BFVEvaluationBuffer.
func newBFVEvaluationBuffer[T tfhe.TorusInt](params tfhe.Parameters[T]) bfvEvaluationBuffer[T] {
	tensorRank := params.GLWERank() * (params.GLWERank() + 3) / 2
	return bfvEvaluationBuffer[T]{
		ctMulFourier: [2]tfhe.FourierGLWECiphertext[T]{
			tfhe.NewFourierGLWECiphertext(params),
			tfhe.NewFourierGLWECiphertext(params),
		},
		ctTensor:        tfhe.NewGLWECiphertextCustom[T](tensorRank, params.PolyDegree()),
		ctTensorFourier: tfhe.NewFourierGLWECiphertextCustom[T](tensorRank, params.PolyDegree()),
		ctPermute:       tfhe.NewGLWECiphertext(params),
		ctPack:          tfhe.NewGLWECiphertext(params),
	}
}

// ShallowCopy creates a shallow copy of this BFVEvaluator.
func (e *BFVEvaluator[T]) ShallowCopy() *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),
		Parameters:    e.Parameters,
		EvaluationKey: e.EvaluationKey,
		buffer:        newBFVEvaluationBuffer(e.Parameters),
	}
}

// Tensor computes the tensor product of two ciphertexts.
// ctOut has GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) Tensor(ct0, ct1 tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	tensorRank := e.Parameters.GLWERank() * (e.Parameters.GLWERank() + 3) / 2
	ctOut := tfhe.NewGLWECiphertextCustom[T](tensorRank, e.Parameters.PolyDegree())
	e.TensorAssign(ct0, ct1, ctOut)
	return ctOut
}

// TensorAssign computes the tensor product of two ciphertexts and assigns the result to ctOut.
// ctOut should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) TensorAssign(ct0, ct1, ctOut tfhe.GLWECiphertext[T]) {
	e.BaseEvaluator.ToFourierGLWECiphertextAssign(ct0, e.buffer.ctMulFourier[0])
	e.BaseEvaluator.ToFourierGLWECiphertextAssign(ct1, e.buffer.ctMulFourier[1])

	tensorIdx := 0
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		e.PolyEvaluator.MulFourierPolyAssign(e.buffer.ctMulFourier[0].Value[i], e.buffer.ctMulFourier[1].Value[i], e.buffer.ctTensorFourier.Value[tensorIdx])
		tensorIdx++
		for j := i + 1; j < e.Parameters.GLWERank()+1; j++ {
			e.PolyEvaluator.MulFourierPolyAssign(e.buffer.ctMulFourier[0].Value[i], e.buffer.ctMulFourier[1].Value[j], e.buffer.ctTensorFourier.Value[tensorIdx])
			e.PolyEvaluator.MulAddFourierPolyAssign(e.buffer.ctMulFourier[0].Value[j], e.buffer.ctMulFourier[1].Value[i], e.buffer.ctTensorFourier.Value[tensorIdx])
			tensorIdx++
		}
	}

	tensorRank := e.Parameters.GLWERank() * (e.Parameters.GLWERank() + 3) / 2
	for i := 0; i < tensorRank+1; i++ {
		e.PolyEvaluator.FloatMulFourierPolyAssign(e.buffer.ctTensorFourier.Value[i], 1/float64(e.Parameters.Scale()), e.buffer.ctTensorFourier.Value[i])
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctTensorFourier.Value[i], e.buffer.ctTensor.Value[i])
	}
}

// Relinearize relinearizes a tensor product of two ciphertexts.
// ct should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) Relinearize(ct tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.RelinearizeAssign(ct, ctOut)
	return ctOut
}

// RelinearizeAssign relinearizes a tensor product of two ciphertexts and assigns the result to ctOut.
// ct should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) RelinearizeAssign(ct, ctOut tfhe.GLWECiphertext[T]) {
	tensorRank := e.Parameters.GLWERank() * (e.Parameters.GLWERank() + 3) / 2
	for i := 0; i < e.Parameters.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(e.buffer.ctTensor.Value[i])
	}
	for i, ii := e.Parameters.GLWERank()+1, 0; i < tensorRank+1; i, ii = i+1, ii+1 {
		e.BaseEvaluator.GadgetProductAddGLWEAssign(e.EvaluationKey.RelinKey.Value[ii], e.buffer.ctTensor.Value[i], ctOut)
	}
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
	e.BaseEvaluator.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKeys[d], ctOut)
}

// LWEToGLWECiphertext packs a LWE ciphertext to GLWE ciphertext.
func (e *BFVEvaluator[T]) LWEToGLWECiphertext(ct tfhe.LWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.LWEToGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// LWEToGLWECiphertextAssign packs a LWE ciphertext to GLWE ciphertext.
func (e *BFVEvaluator[T]) LWEToGLWECiphertextAssign(ct tfhe.LWECiphertext[T], ctOut tfhe.GLWECiphertext[T]) {
	ctOut.Value[0].Clear()
	ctOut.Value[0].Coeffs[0] = num.DivRoundBits(ct.Value[0], e.Parameters.LogPolyDegree())

	for i := 0; i < e.Parameters.GLWERank(); i++ {
		ctOut.Value[1+i].Coeffs[0] = num.DivRoundBits(ct.Value[1+i*e.Parameters.PolyDegree()], e.Parameters.LogPolyDegree())
		for j := 1; j < e.Parameters.PolyDegree(); j++ {
			ctOut.Value[1+i].Coeffs[e.Parameters.PolyDegree()-j] = -num.DivRoundBits(ct.Value[1+i*e.Parameters.PolyDegree()+j], e.Parameters.LogPolyDegree())
		}
	}

	for i := 0; i < e.Parameters.LogPolyDegree(); i++ {
		e.PermuteAssign(ctOut, 1<<(e.Parameters.LogPolyDegree()-i)+1, e.buffer.ctPack)
		e.BaseEvaluator.AddGLWEAssign(ctOut, e.buffer.ctPack, ctOut)
	}
}
