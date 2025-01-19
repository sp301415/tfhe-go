package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FHEWEvaluator wraps around [tfhe.Evaluator] and implements FHEW blind rotation.
type FHEWEvaluator[T tfhe.TorusInt] struct {
	// Evaluator is an embedded [tfhe.Evaluator] for this FHEWEvaluator.
	*tfhe.Evaluator[T]

	// Parameters is the parameters for this Evaluator.
	Parameters FHEWParameters[T]

	// EvaluationKey is the evaluation key for this Evaluator.
	EvaluationKey FHEWEvaluationKey[T]

	// autIdxMap holds the map ±5^i -> ±i mod 2N.
	autIdxMap []int

	buffer fhewEvaluationBuffer[T]
}

// fhewEvaluationBuffer contains buffer values for FHEWEvaluator.
type fhewEvaluationBuffer[T tfhe.TorusInt] struct {
	// ctFourierAcc is the fourier transformed accumulator in Blind Rotation.
	ctFourierAcc tfhe.FourierGLWECiphertext[T]
	// ctAccFourierDecomposed is the decomposed ctAcc in Blind Rotation.
	ctAccFourierDecomposed [][]poly.FourierPoly

	// ctPermute is the permuted accumulator for bootstrapping.
	ctPermute tfhe.GLWECiphertext[T]
	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate tfhe.GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract tfhe.LWECiphertext[T]
	// ctKeySwitchForBootstrap is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitchForBootstrap tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewFHEWEvaluator allocates an empty FHEWEvaluator.
func NewFHEWEvaluator[T tfhe.TorusInt](params FHEWParameters[T], evk FHEWEvaluationKey[T]) *FHEWEvaluator[T] {
	autIdxMap := make([]int, 2*params.baseParameters.PolyDegree())
	autIdx := 1
	for i := 0; i < params.baseParameters.PolyDegree()/2; i++ {
		autIdxMap[autIdx] = i
		autIdxMap[2*params.baseParameters.PolyDegree()-autIdx] = -i
		autIdx = (autIdx * 5) % (2 * params.baseParameters.PolyDegree())
	}
	autIdxMap[2*params.baseParameters.PolyDegree()-1] = 2 * params.baseParameters.PolyDegree()

	return &FHEWEvaluator[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParameters, tfhe.EvaluationKey[T]{KeySwitchKey: evk.KeySwitchKey}),

		Parameters: params,

		EvaluationKey: evk,

		autIdxMap: autIdxMap,

		buffer: newFHEWEvaluationBuffer(params),
	}
}

// newFHEWEvaluationBuffer allocates an empty evaluationBuffer.
func newFHEWEvaluationBuffer[T tfhe.TorusInt](params FHEWParameters[T]) fhewEvaluationBuffer[T] {
	ctAccFourierDecomposed := make([][]poly.FourierPoly, params.baseParameters.GLWERank()+1)
	for i := 0; i < params.baseParameters.GLWERank()+1; i++ {
		ctAccFourierDecomposed[i] = make([]poly.FourierPoly, params.baseParameters.BlindRotateParameters().Level())
		for j := 0; j < params.baseParameters.BlindRotateParameters().Level(); j++ {
			ctAccFourierDecomposed[i][j] = poly.NewFourierPoly(params.baseParameters.PolyDegree())
		}
	}

	return fhewEvaluationBuffer[T]{
		ctFourierAcc:           tfhe.NewFourierGLWECiphertext(params.baseParameters),
		ctAccFourierDecomposed: ctAccFourierDecomposed,

		ctPermute:               tfhe.NewGLWECiphertext(params.baseParameters),
		ctRotate:                tfhe.NewGLWECiphertext(params.baseParameters),
		ctExtract:               tfhe.NewLWECiphertextCustom[T](params.baseParameters.GLWEDimension()),
		ctKeySwitchForBootstrap: tfhe.NewLWECiphertextCustom[T](params.baseParameters.LWEDimension()),

		lut: tfhe.NewLookUpTable(params.baseParameters),
	}
}

// ShallowCopy creates a shallow copy of this FHEWEvaluator.
// Returned FHEWEvaluator is safe for concurrent use.
func (e *FHEWEvaluator[T]) ShallowCopy() *FHEWEvaluator[T] {
	return &FHEWEvaluator[T]{
		Evaluator: e.Evaluator.ShallowCopy(),

		Parameters: e.Parameters,

		EvaluationKey: e.EvaluationKey,

		autIdxMap: e.autIdxMap,

		buffer: newFHEWEvaluationBuffer(e.Parameters),
	}
}
