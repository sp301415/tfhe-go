package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// ManyLUTEvaluator wraps around [tfhe.Evaluator], and implements PBSManyLUT algorithm.
// For more details, see https://eprint.iacr.org/2021/729.
type ManyLUTEvaluator[T tfhe.TorusInt] struct {
	*tfhe.Evaluator[T]

	// lutCount is the number of LUTs to evaluate at once.
	lutCount int
	// logLUTCount equals log2(lutCount).
	logLUTCount int

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
//
// Panics when PolyDegree does not equal LookUpTableSize,
// or when lutCount is not a power of 2.
func NewManyLUTEvaluator[T tfhe.TorusInt](params tfhe.Parameters[T], lutCount int, evk tfhe.EvaluationKey[T]) *ManyLUTEvaluator[T] {
	switch {
	case params.PolyDegree() != params.LookUpTableSize():
		panic("PolyDegree must equal LookUpTableSize")
	case !num.IsPowerOfTwo(lutCount):
		panic("lutCount not power of two")
	}

	return &ManyLUTEvaluator[T]{
		Evaluator: tfhe.NewEvaluator(params, evk),

		lutCount:    lutCount,
		logLUTCount: num.Log2(lutCount),

		buffer: newManyLUTEvaluationBuffer(params),
	}
}

// newManyLUTEvaluationBuffer creates a new manyLUTEvaluationBuffer.
func newManyLUTEvaluationBuffer[T tfhe.TorusInt](params tfhe.Parameters[T]) manyLUTEvaluationBuffer[T] {
	ctAccFourierDecomposed := make([][]poly.FourierPoly, params.GLWERank()+1)
	for i := 0; i < params.GLWERank()+1; i++ {
		ctAccFourierDecomposed[i] = make([]poly.FourierPoly, params.BlindRotateParameters().Level())
		for j := 0; j < params.BlindRotateParameters().Level(); j++ {
			ctAccFourierDecomposed[i][j] = poly.NewFourierPoly(params.PolyDegree())
		}
	}

	return manyLUTEvaluationBuffer[T]{
		ctFourierAcc:           tfhe.NewFourierGLWECiphertext(params),
		ctBlockFourierAcc:      tfhe.NewFourierGLWECiphertext(params),
		ctAccFourierDecomposed: ctAccFourierDecomposed,
		fMono:                  poly.NewFourierPoly(params.PolyDegree()),

		ctRotate:                tfhe.NewGLWECiphertext(params),
		ctExtract:               tfhe.NewLWECiphertextCustom[T](params.GLWEDimension()),
		ctKeySwitchForBootstrap: tfhe.NewLWECiphertextCustom[T](params.LWEDimension()),

		lut: tfhe.NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *ManyLUTEvaluator[T]) ShallowCopy() *ManyLUTEvaluator[T] {
	return &ManyLUTEvaluator[T]{
		Evaluator: e.Evaluator.ShallowCopy(),
		lutCount:  e.lutCount,
		buffer:    newManyLUTEvaluationBuffer(e.Parameters),
	}
}

// LUTCount returns the number of LUTs to evaluate at once.
func (e *ManyLUTEvaluator[T]) LUTCount() int {
	return e.lutCount
}
