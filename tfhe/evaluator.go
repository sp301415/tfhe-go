package tfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/poly"
)

// Evaluator evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
//
// Evaluator is not safe for concurrent use.
// Use [*Evaluator.SafeCopy] to get a safe copy.
type Evaluator[T TorusInt] struct {
	// Encoder is an embedded encoder for this Evaluator.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Evaluator.
	*GLWETransformer[T]

	// Params is the parameters for this Evaluator.
	Params Parameters[T]

	// Decomposer is an Decomposer for this Evaluator.
	Decomposer *Decomposer[T]
	// PolyEvaluator is a PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]

	// EvalKey is the evaluation key for this Evaluator.
	EvalKey EvaluationKey[T]

	// modSwitchConst is a constant for modulus switching.
	modSwitchConst float64

	buf evaluatorBuffer[T]
}

// evaluatorBuffer is a buffer for Evaluator.
type evaluatorBuffer[T TorusInt] struct {
	// fpMul is the fourier transformed polynomial for multiplications.
	fpMul poly.FFTPoly

	// ctProdLWE is the LWE ciphertext buffer for ExternalProductLWE and KeySwitchLWE.
	ctProdLWE LWECiphertext[T]
	// fctProdGLWE is the fourier transformed ctGLWEOut in ExternalProductGLWE and KeySwitchGLWE.
	fctProdGLWE FFTGLWECiphertext[T]
	// ctCMux is ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// ctAcc is the accumulator in BlindRotateExtended.
	// This has length LUTExtendFactor.
	ctAcc []GLWECiphertext[T]
	// fctAcc is the fourier transformed accumulator in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length LUTExtendFactor.
	fctAcc []FFTGLWECiphertext[T]
	// fctBlockAcc is the auxiliary accumulator in BlindRotateBlock and BlindRotateExtended.
	fctBlockAcc []FFTGLWECiphertext[T]
	// fctAccDcmp is the decomposed ctAcc in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length LUTExtendFactor.
	fctAccDcmp [][][]poly.FFTPoly
	// fMono is the fourier transformed monomial in Blind Rotation.
	fMono poly.FFTPoly

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitch is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitch LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
	// lutRaw is an full-sized LUT.
	lutRaw []T
}

// NewEvaluator creates a new Evaluator based on parameters.
// This does not copy evaluation keys, since they may be large.
func NewEvaluator[T TorusInt](params Parameters[T], evk EvaluationKey[T]) *Evaluator[T] {
	decomposer := NewDecomposer[T](params.polyRank)
	decomposer.ScalarBuffer(params.keySwitchParams)
	decomposer.PolyBuffer(params.blindRotateParams)
	decomposer.FFTPolyBuffer(params.blindRotateParams)

	return &Evaluator[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer[T](params.polyRank),

		Params: params,

		Decomposer:    decomposer,
		PolyEvaluator: poly.NewEvaluator[T](params.polyRank),

		EvalKey: evk,

		modSwitchConst: float64(2*params.lutSize) / math.Exp2(float64(params.logQ)),

		buf: newEvaluatorBuffer(params),
	}
}

// newEvaluatorBuffer creates a new evaluatorBuffer.
func newEvaluatorBuffer[T TorusInt](params Parameters[T]) evaluatorBuffer[T] {
	ctAcc := make([]GLWECiphertext[T], params.lutExtendFactor)
	ctFFTAcc := make([]FFTGLWECiphertext[T], params.lutExtendFactor)
	ctBlockFourierAcc := make([]FFTGLWECiphertext[T], params.lutExtendFactor)
	for i := 0; i < params.lutExtendFactor; i++ {
		ctAcc[i] = NewGLWECiphertext(params)
		ctFFTAcc[i] = NewFFTGLWECiphertext(params)
		ctBlockFourierAcc[i] = NewFFTGLWECiphertext(params)
	}

	fctAccDcmp := make([][][]poly.FFTPoly, params.lutExtendFactor)
	for i := 0; i < params.lutExtendFactor; i++ {
		fctAccDcmp[i] = make([][]poly.FFTPoly, params.glweRank+1)
		for j := 0; j < params.glweRank+1; j++ {
			fctAccDcmp[i][j] = make([]poly.FFTPoly, params.blindRotateParams.level)
			for k := 0; k < params.blindRotateParams.level; k++ {
				fctAccDcmp[i][j][k] = poly.NewFFTPoly(params.polyRank)
			}
		}
	}

	return evaluatorBuffer[T]{
		fpMul: poly.NewFFTPoly(params.polyRank),

		ctProdLWE:   NewLWECiphertext(params),
		fctProdGLWE: NewFFTGLWECiphertext(params),
		ctCMux:      NewGLWECiphertext(params),

		ctAcc:       ctAcc,
		fctAcc:      ctFFTAcc,
		fctBlockAcc: ctBlockFourierAcc,
		fctAccDcmp:  fctAccDcmp,
		fMono:       poly.NewFFTPoly(params.polyRank),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   NewLWECiphertextCustom[T](params.glweDimension),
		ctKeySwitch: NewLWECiphertextCustom[T](params.lweDimension),

		lut:    NewLUT(params),
		lutRaw: make([]T, params.lutSize),
	}
}

// SafeCopy returns a thread-safe copy.
func (e *Evaluator[T]) SafeCopy() *Evaluator[T] {
	return &Evaluator[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.SafeCopy(),

		Params: e.Params,

		Decomposer:    e.Decomposer.SafeCopy(),
		PolyEvaluator: e.PolyEvaluator.SafeCopy(),

		EvalKey: e.EvalKey,

		modSwitchConst: e.modSwitchConst,

		buf: newEvaluatorBuffer(e.Params),
	}
}
