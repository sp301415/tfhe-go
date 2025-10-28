package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ManyLUTEvaluator wraps around [tfhe.Evaluator], and implements PBSManyLUT algorithm.
// For more details, see https://eprint.iacr.org/2021/729.
//
// ManyLUTEvaluator is not safe for concurrent use.
// Use [*ManyLUTEvaluator.SafeCopy] to get a safe copy.
type ManyLUTEvaluator[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this ManyLUTEvaluator.
	*tfhe.Evaluator[T]

	// Params is the parameters for this ManyLUTEvaluator.
	Params ManyLUTParameters[T]

	buf manyLUTEvaluatorBuffer[T]
}

// manyLUTEvaluatorBuffer is a buffer for ManyLUTEvaluator.
type manyLUTEvaluatorBuffer[T tfhe.TorusInt] struct {
	// ctFFTAcc is the fourier transformed accumulator in Blind Rotation.
	ctFFTAcc tfhe.FFTGLWECiphertext[T]
	// ctFFTBlockAcc is the auxiliary accumulator in BlindRotateBlock.
	ctFFTBlockAcc tfhe.FFTGLWECiphertext[T]
	// ctFFTAccDcmp is the decomposed ctAcc in Blind Rotation.
	ctFFTAccDcmp [][]poly.FFTPoly
	// fMono is the fourier transformed monomial in Blind Rotation.
	fMono poly.FFTPoly

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate tfhe.GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract tfhe.LWECiphertext[T]
	// ctKeySwitch is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitch tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewManyLUTEvaluator creates a new ManyLUTEvaluator.
func NewManyLUTEvaluator[T tfhe.TorusInt](params ManyLUTParameters[T], evk tfhe.EvaluationKey[T]) *ManyLUTEvaluator[T] {
	return &ManyLUTEvaluator[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParams, evk),

		Params: params,

		buf: newManyLUTEvaluatorBuffer(params),
	}
}

// newManyLUTEvaluatorBuffer creates a new manyLUTEvaluatorBuffer.
func newManyLUTEvaluatorBuffer[T tfhe.TorusInt](params ManyLUTParameters[T]) manyLUTEvaluatorBuffer[T] {
	ctFFTAccDcmp := make([][]poly.FFTPoly, params.baseParams.GLWERank()+1)
	for i := 0; i < params.baseParams.GLWERank()+1; i++ {
		ctFFTAccDcmp[i] = make([]poly.FFTPoly, params.baseParams.BlindRotateParams().Level())
		for j := 0; j < params.baseParams.BlindRotateParams().Level(); j++ {
			ctFFTAccDcmp[i][j] = poly.NewFFTPoly(params.baseParams.PolyRank())
		}
	}

	return manyLUTEvaluatorBuffer[T]{
		ctFFTAcc:      tfhe.NewFFTGLWECiphertext(params.baseParams),
		ctFFTBlockAcc: tfhe.NewFFTGLWECiphertext(params.baseParams),
		ctFFTAccDcmp:  ctFFTAccDcmp,
		fMono:         poly.NewFFTPoly(params.baseParams.PolyRank()),

		ctRotate:    tfhe.NewGLWECiphertext(params.baseParams),
		ctExtract:   tfhe.NewLWECiphertextCustom[T](params.baseParams.GLWEDimension()),
		ctKeySwitch: tfhe.NewLWECiphertextCustom[T](params.baseParams.LWEDimension()),

		lut: tfhe.NewLUT(params.baseParams),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *ManyLUTEvaluator[T]) SafeCopy() *ManyLUTEvaluator[T] {
	return &ManyLUTEvaluator[T]{
		Evaluator: e.Evaluator.SafeCopy(),
		Params:    e.Params,
		buf:       newManyLUTEvaluatorBuffer(e.Params),
	}
}
