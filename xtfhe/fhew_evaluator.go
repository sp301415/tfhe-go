package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWEvaluator wraps around [tfhe.Evaluator] and implements FHEW blind rotation.
//
// FHEWEvaluator is not safe for concurrent use.
// Use [*FHEWEvaluator.SafeCopy] to get a safe copy.
type FHEWEvaluator[T tfhe.TorusInt] struct {
	// Evaluator is an embedded [tfhe.Evaluator] for this FHEWEvaluator.
	*tfhe.Evaluator[T]

	// Params is the parameters for this Evaluator.
	Params FHEWParameters[T]

	// EvalKey is the evaluation key for this Evaluator.
	EvalKey FHEWEvaluationKey[T]

	// autIdxMap holds the map ±5^i -> ±i mod 2N.
	autIdxMap []int

	buf fhewEvaluatorBuffer[T]
}

// fhewEvaluatorBuffer is a buffer for FHEWEvaluator.
type fhewEvaluatorBuffer[T tfhe.TorusInt] struct {
	// fctAcc is the fourier transformed accumulator in Blind Rotation.
	fctAcc tfhe.FFTGLWECiphertext[T]
	// fctAccDcmp is the decomposed ctAcc in Blind Rotation.
	fctAccDcmp [][]poly.FFTPoly

	// ctPermute is the permuted accumulator for bootstrapping.
	ctPermute tfhe.GLWECiphertext[T]
	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate tfhe.GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract tfhe.LWECiphertext[T]
	// ctKeySwitch is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitch tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewFHEWEvaluator creates a new FHEWEvaluator.
func NewFHEWEvaluator[T tfhe.TorusInt](params FHEWParameters[T], evk FHEWEvaluationKey[T]) *FHEWEvaluator[T] {
	autIdxMap := make([]int, 2*params.baseParams.PolyRank())
	autIdx := 1
	for i := 0; i < params.baseParams.PolyRank()/2; i++ {
		autIdxMap[autIdx] = i
		autIdxMap[2*params.baseParams.PolyRank()-autIdx] = -i
		autIdx = (autIdx * 5) % (2 * params.baseParams.PolyRank())
	}
	autIdxMap[2*params.baseParams.PolyRank()-1] = 2 * params.baseParams.PolyRank()

	return &FHEWEvaluator[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParams, tfhe.EvaluationKey[T]{KeySwitchKey: evk.KeySwitchKey}),

		Params: params,

		EvalKey: evk,

		autIdxMap: autIdxMap,

		buf: newFHEWEvaluatorBuffer(params),
	}
}

// newFHEWEvaluatorBuffer creates a new fhewEvaluatorBuffer.
func newFHEWEvaluatorBuffer[T tfhe.TorusInt](params FHEWParameters[T]) fhewEvaluatorBuffer[T] {
	fctAccDcmp := make([][]poly.FFTPoly, params.baseParams.GLWERank()+1)
	for i := 0; i < params.baseParams.GLWERank()+1; i++ {
		fctAccDcmp[i] = make([]poly.FFTPoly, params.baseParams.BlindRotateParams().Level())
		for j := 0; j < params.baseParams.BlindRotateParams().Level(); j++ {
			fctAccDcmp[i][j] = poly.NewFFTPoly(params.baseParams.PolyRank())
		}
	}

	return fhewEvaluatorBuffer[T]{
		fctAcc:     tfhe.NewFFTGLWECiphertext(params.baseParams),
		fctAccDcmp: fctAccDcmp,

		ctPermute:   tfhe.NewGLWECiphertext(params.baseParams),
		ctRotate:    tfhe.NewGLWECiphertext(params.baseParams),
		ctExtract:   tfhe.NewLWECiphertextCustom[T](params.baseParams.GLWEDimension()),
		ctKeySwitch: tfhe.NewLWECiphertextCustom[T](params.baseParams.LWEDimension()),

		lut: tfhe.NewLUT(params.baseParams),
	}
}

// SafeCopy creates a shallow copy of this FHEWEvaluator.
// Returned FHEWEvaluator is safe for concurrent use.
func (e *FHEWEvaluator[T]) SafeCopy() *FHEWEvaluator[T] {
	return &FHEWEvaluator[T]{
		Evaluator: e.Evaluator.SafeCopy(),

		Params: e.Params,

		EvalKey: e.EvalKey,

		autIdxMap: e.autIdxMap,

		buf: newFHEWEvaluatorBuffer(e.Params),
	}
}
