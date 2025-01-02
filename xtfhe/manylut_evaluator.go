package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ManyLUTEvaluator wraps around [tfhe.Evaluator], and implements PBSManyLUT algorithm.
// For more details, see https://eprint.iacr.org/2021/729.
type ManyLUTEvaluator[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this ManyLUTEvaluator.
	*tfhe.Evaluator[T]

	// Parameters is the parameters for this ManyLUTEvaluator.
	Parameters ManyLUTParameters[T]

	// buffer is the buffer values for this ManyLUTEvaluator.
	buffer manyLUTEvaluationBuffer[T]
}

// manyLUTEvaluationBuffer contains buffer values for ManyLUTEvaluator.
type manyLUTEvaluationBuffer[T tfhe.TorusInt] struct {
	// ctFourierAcc is the fourier transformed accumulator in Blind Rotation.
	ctFourierAcc tfhe.FourierGLWECiphertext[T]
	// ctBlockFourierAcc is the auxiliary accumulator in BlindRotateBlock.
	ctBlockFourierAcc tfhe.FourierGLWECiphertext[T]
	// ctAccFourierDecomposed is the decomposed ctAcc in Blind Rotation.
	ctAccFourierDecomposed [][]poly.FourierPoly
	// fMono is the fourier transformed monomial in Blind Rotation.
	fMono poly.FourierPoly

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate tfhe.GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract tfhe.LWECiphertext[T]
	// ctKeySwitchForBootstrap is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitchForBootstrap tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewManyLUTEvaluator creates a new ManyLUTEvaluator.
func NewManyLUTEvaluator[T tfhe.TorusInt](params ManyLUTParameters[T], evk tfhe.EvaluationKey[T]) *ManyLUTEvaluator[T] {
	return &ManyLUTEvaluator[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParameters, evk),

		Parameters: params,

		buffer: newManyLUTEvaluationBuffer(params),
	}
}

// newManyLUTEvaluationBuffer creates a new manyLUTEvaluationBuffer.
func newManyLUTEvaluationBuffer[T tfhe.TorusInt](params ManyLUTParameters[T]) manyLUTEvaluationBuffer[T] {
	ctAccFourierDecomposed := make([][]poly.FourierPoly, params.baseParameters.GLWERank()+1)
	for i := 0; i < params.baseParameters.GLWERank()+1; i++ {
		ctAccFourierDecomposed[i] = make([]poly.FourierPoly, params.baseParameters.BlindRotateParameters().Level())
		for j := 0; j < params.baseParameters.BlindRotateParameters().Level(); j++ {
			ctAccFourierDecomposed[i][j] = poly.NewFourierPoly(params.baseParameters.PolyDegree())
		}
	}

	return manyLUTEvaluationBuffer[T]{
		ctFourierAcc:           tfhe.NewFourierGLWECiphertext(params.baseParameters),
		ctBlockFourierAcc:      tfhe.NewFourierGLWECiphertext(params.baseParameters),
		ctAccFourierDecomposed: ctAccFourierDecomposed,
		fMono:                  poly.NewFourierPoly(params.baseParameters.PolyDegree()),

		ctRotate:                tfhe.NewGLWECiphertext(params.baseParameters),
		ctExtract:               tfhe.NewLWECiphertextCustom[T](params.baseParameters.GLWEDimension()),
		ctKeySwitchForBootstrap: tfhe.NewLWECiphertextCustom[T](params.baseParameters.LWEDimension()),

		lut: tfhe.NewLookUpTable(params.baseParameters),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *ManyLUTEvaluator[T]) ShallowCopy() *ManyLUTEvaluator[T] {
	return &ManyLUTEvaluator[T]{
		Evaluator:  e.Evaluator.ShallowCopy(),
		Parameters: e.Parameters,
		buffer:     newManyLUTEvaluationBuffer(e.Parameters),
	}
}
