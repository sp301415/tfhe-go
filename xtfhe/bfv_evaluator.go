package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVEvaluator evaluates BFV-type operations on GLWE ciphertexts.
//
// BFVEvaluator is not safe for concurrent use.
// Use [*BFVEvaluator.SafeCopy] to get a safe copy.
type BFVEvaluator[T tfhe.TorusInt] struct {
	// Evaluator is a base evaluator for this BFVEvaluator.
	// Note that it does not hold evaluaation keys, so bootstrapping is not supported.
	Evaluator *tfhe.Evaluator[T]
	// PolyEvaluator is a PolyEvaluator for this BFVEvaluator.
	PolyEvaluator *poly.Evaluator[T]

	// Params is the parameters for this BFVEvaluator.
	Params tfhe.Parameters[T]

	// EvalKey is the keyswitching keys for this BFVEvaluator.
	EvalKey BFVEvaluationKey[T]

	buf bfvEvaluatorBuffer[T]
}

// bfvEvaluatorBuffer is a buffer for BFV type evaluation.
type bfvEvaluatorBuffer[T tfhe.TorusInt] struct {
	// ctFFT is the fourier transformed ciphertext for BFV multiplication.
	fctMul [2]tfhe.FFTGLWECiphertext[T]
	// ctTensor is the tensored ciphertext for BFV multiplication.
	ctTensor tfhe.GLWECiphertext[T]
	// fctTensor is the fourier transformed ctTensor.
	fctTensor tfhe.FFTGLWECiphertext[T]
	// ctPermute is the permuted ciphertext for BFV automorphism.
	ctPermute tfhe.GLWECiphertext[T]
	// ctPack is the permuted ciphertext for LWEToGLWECiphertext.
	ctPack tfhe.GLWECiphertext[T]
}

// NewBFVEvaluator creates a new BFVEvaluator.
func NewBFVEvaluator[T tfhe.TorusInt](params tfhe.Parameters[T], evk BFVEvaluationKey[T]) *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		Evaluator:     tfhe.NewEvaluator(params, tfhe.EvaluationKey[T]{}),
		PolyEvaluator: poly.NewEvaluator[T](params.PolyRank()),
		Params:        params,
		EvalKey:       evk,
		buf:           newBFVEvaluatorBuffer(params),
	}
}

// newBFVEvaluatorBuffer creates a new BFVEvaluatorBuffer.
func newBFVEvaluatorBuffer[T tfhe.TorusInt](params tfhe.Parameters[T]) bfvEvaluatorBuffer[T] {
	tensorRank := params.GLWERank() * (params.GLWERank() + 3) / 2
	return bfvEvaluatorBuffer[T]{
		fctMul: [2]tfhe.FFTGLWECiphertext[T]{
			tfhe.NewFFTGLWECiphertext(params),
			tfhe.NewFFTGLWECiphertext(params),
		},
		ctTensor:  tfhe.NewGLWECiphertextCustom[T](tensorRank, params.PolyRank()),
		fctTensor: tfhe.NewFFTGLWECiphertextCustom[T](tensorRank, params.PolyRank()),
		ctPermute: tfhe.NewGLWECiphertext(params),
		ctPack:    tfhe.NewGLWECiphertext(params),
	}
}

// SafeCopy creates a shallow copy of this BFVEvaluator.
func (e *BFVEvaluator[T]) SafeCopy() *BFVEvaluator[T] {
	return &BFVEvaluator[T]{
		Evaluator:     e.Evaluator.SafeCopy(),
		PolyEvaluator: e.PolyEvaluator.SafeCopy(),
		Params:        e.Params,
		EvalKey:       e.EvalKey,
		buf:           newBFVEvaluatorBuffer(e.Params),
	}
}

// Tensor computes the tensor product of two ciphertexts.
// ctOut has GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) Tensor(ct0, ct1 tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	tensorRank := e.Params.GLWERank() * (e.Params.GLWERank() + 3) / 2
	ctOut := tfhe.NewGLWECiphertextCustom[T](tensorRank, e.Params.PolyRank())
	e.TensorTo(ctOut, ct0, ct1)
	return ctOut
}

// TensorTo computes the tensor product of two ciphertexts and assigns the result to ctOut.
// ctOut should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) TensorTo(ctOut, ct0, ct1 tfhe.GLWECiphertext[T]) {
	e.Evaluator.FFTGLWECiphertextTo(e.buf.fctMul[0], ct0)
	e.Evaluator.FFTGLWECiphertextTo(e.buf.fctMul[1], ct1)

	tensorIdx := 0
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		e.PolyEvaluator.MulFFTPolyTo(e.buf.fctTensor.Value[tensorIdx], e.buf.fctMul[0].Value[i], e.buf.fctMul[1].Value[i])
		tensorIdx++
		for j := i + 1; j < e.Params.GLWERank()+1; j++ {
			e.PolyEvaluator.MulFFTPolyTo(e.buf.fctTensor.Value[tensorIdx], e.buf.fctMul[0].Value[i], e.buf.fctMul[1].Value[j])
			e.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctTensor.Value[tensorIdx], e.buf.fctMul[0].Value[j], e.buf.fctMul[1].Value[i])
			tensorIdx++
		}
	}

	tensorRank := e.Params.GLWERank() * (e.Params.GLWERank() + 3) / 2
	for i := 0; i < tensorRank+1; i++ {
		e.PolyEvaluator.FloatMulFFTPolyTo(e.buf.fctTensor.Value[i], e.buf.fctTensor.Value[i], 1/float64(e.Params.Scale()))
		e.PolyEvaluator.InvFFTToUnsafe(e.buf.ctTensor.Value[i], e.buf.fctTensor.Value[i])
	}
}

// Relinearize relinearizes a tensor product of two ciphertexts.
// ct should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) Relinearize(ct tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params)
	e.RelinearizeTo(ctOut, ct)
	return ctOut
}

// RelinearizeTo relinearizes a tensor product of two ciphertexts and assigns the result to ctOut.
// ct should have GLWERank = params.GLWERank + (params.GLWERank + 3) / 2.
func (e *BFVEvaluator[T]) RelinearizeTo(ctOut, ct tfhe.GLWECiphertext[T]) {
	tensorRank := e.Params.GLWERank() * (e.Params.GLWERank() + 3) / 2
	for i := 0; i < e.Params.GLWERank()+1; i++ {
		ctOut.Value[i].CopyFrom(e.buf.ctTensor.Value[i])
	}
	for i, ii := e.Params.GLWERank()+1, 0; i < tensorRank+1; i, ii = i+1, ii+1 {
		e.Evaluator.GadgetProdAddGLWETo(ctOut, e.EvalKey.RelinKey.Value[ii], e.buf.ctTensor.Value[i])
	}
}

// Mul returns ctOut = ct0 * ct1, using BFV multiplication.
func (e *BFVEvaluator[T]) Mul(ct0, ct1 tfhe.GLWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params)
	e.MulTo(ctOut, ct0, ct1)
	return ctOut
}

// MulTo assigns ctOut = ct0 * ct1, using BFV multiplication.
func (e *BFVEvaluator[T]) MulTo(ctOut, ct0, ct1 tfhe.GLWECiphertext[T]) {
	e.TensorTo(e.buf.ctTensor, ct0, ct1)
	e.RelinearizeTo(ctOut, e.buf.ctTensor)
}

// Permute returns ctOut = ct(x^d), using BFV automorphism.
//
// Panics if BFVEvaluator does not have galois key for d.
func (e *BFVEvaluator[T]) Permute(ct tfhe.GLWECiphertext[T], d int) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params)
	e.PermuteTo(ctOut, ct, d)
	return ctOut
}

// PermuteTo assigns ctOut = ct(x^d), using BFV automorphism.
//
// Panics if BFVEvaluator does not have galois key for d.
func (e *BFVEvaluator[T]) PermuteTo(ctOut, ct tfhe.GLWECiphertext[T], d int) {
	e.Evaluator.PermuteGLWETo(e.buf.ctPermute, ct, d)
	e.Evaluator.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKeys[d])
}

// Pack packs a LWE ciphertext to GLWE ciphertext.
func (e *BFVEvaluator[T]) Pack(ct tfhe.LWECiphertext[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params)
	e.PackTo(ctOut, ct)
	return ctOut
}

// PackTo packs a LWE ciphertext to GLWE ciphertext.
func (e *BFVEvaluator[T]) PackTo(ctOut tfhe.GLWECiphertext[T], ct tfhe.LWECiphertext[T]) {
	ctOut.Value[0].Clear()
	ctOut.Value[0].Coeffs[0] = ct.Value[0]

	for i := 0; i < e.Params.GLWERank(); i++ {
		ctOut.Value[1+i].Coeffs[0] = ct.Value[1+i*e.Params.PolyRank()]
		for j := 1; j < e.Params.PolyRank(); j++ {
			ctOut.Value[1+i].Coeffs[e.Params.PolyRank()-j] = -ct.Value[1+i*e.Params.PolyRank()+j]
		}
	}

	for i := 0; i < e.Params.LogPolyRank(); i++ {
		for j := 0; j < e.Params.GLWERank()+1; j++ {
			for l := 0; l < e.Params.PolyRank(); l++ {
				ctOut.Value[j].Coeffs[l] = num.DivRoundBits(ctOut.Value[j].Coeffs[l], 1)
			}
		}
		e.PermuteTo(e.buf.ctPack, ctOut, (1<<(i+1))+1)
		e.Evaluator.AddGLWETo(ctOut, ctOut, e.buf.ctPack)
	}
}
