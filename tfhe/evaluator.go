package tfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/poly"
)

// Evaluator evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
//
// Evaluator is not safe for concurrent use.
// Use [*Evaluator.ShallowCopy] to get a safe copy.
type Evaluator[T TorusInt] struct {
	// Encoder is an embedded encoder for this Evaluator.
	*Encoder[T]
	// GLWETransformer is an embedded GLWETransformer for this Evaluator.
	*GLWETransformer[T]
	// Decomposer is an embedded Decomposer for this Evaluator.
	*Decomposer[T]

	// Parameters is the parameters for this Evaluator.
	Parameters Parameters[T]

	// PolyEvaluator is the PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]

	// EvaluationKey is the evaluation key for this Evaluator.
	EvaluationKey EvaluationKey[T]

	// modSwitchConstant is a constant for modulus switching.
	modSwitchConstant float64

	// buffer is the buffer values for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T TorusInt] struct {
	// fpMul is the fourier transformed polynomial for multiplications.
	fpMul poly.FourierPoly
	// ctFourierProd is the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux is ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// ctAcc is the accumulator in BlindRotateExtended.
	// This has length PolyExtendFactor.
	ctAcc []GLWECiphertext[T]
	// ctFourierAcc is the fourier transformed accumulator in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExtendFactor.
	ctFourierAcc []FourierGLWECiphertext[T]
	// ctBlockFourierAcc is the auxiliary accumulator in BlindRotateBlock and BlindRotateExtended.
	ctBlockFourierAcc []FourierGLWECiphertext[T]
	// ctAccFourierDecomposed is the decomposed ctAcc in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExpandFactor.
	ctAccFourierDecomposed [][][]poly.FourierPoly
	// fMono is the fourier transformed monomial in Blind Rotation.
	fMono poly.FourierPoly

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitch is the LWEDimension sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
}

// NewEvaluator allocates an empty Evaluator based on parameters.
// This does not copy evaluation keys, since they may be large.
func NewEvaluator[T TorusInt](params Parameters[T], evk EvaluationKey[T]) *Evaluator[T] {
	decomposer := NewDecomposer[T](params.polyDegree)
	decomposer.ScalarDecomposedBuffer(params.keyswitchParameters)
	decomposer.PolyDecomposedBuffer(params.bootstrapParameters)
	decomposer.PolyFourierDecomposedBuffer(params.bootstrapParameters)

	return &Evaluator[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer(params),
		Decomposer:      decomposer,

		Parameters: params,

		PolyEvaluator: poly.NewEvaluator[T](params.polyDegree),

		EvaluationKey: evk,

		modSwitchConstant: float64(params.polyExtendFactor) / math.Exp2(float64(params.logQ-params.polyDegreeLog-1)),

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T TorusInt](params Parameters[T]) evaluationBuffer[T] {
	polyDecomposed := make([]poly.Poly[T], params.bootstrapParameters.level)
	polyFourierDecomposed := make([]poly.FourierPoly, params.bootstrapParameters.level)
	for i := 0; i < params.bootstrapParameters.level; i++ {
		polyDecomposed[i] = poly.NewPoly[T](params.polyDegree)
		polyFourierDecomposed[i] = poly.NewFourierPoly(params.polyDegree)
	}

	ctAcc := make([]GLWECiphertext[T], params.polyExtendFactor)
	ctFourierAcc := make([]FourierGLWECiphertext[T], params.polyExtendFactor)
	ctBlockFourierAcc := make([]FourierGLWECiphertext[T], params.polyExtendFactor)
	for i := 0; i < params.polyExtendFactor; i++ {
		ctAcc[i] = NewGLWECiphertext(params)
		ctFourierAcc[i] = NewFourierGLWECiphertext(params)
		ctBlockFourierAcc[i] = NewFourierGLWECiphertext(params)
	}

	ctAccFourierDecomposed := make([][][]poly.FourierPoly, params.polyExtendFactor)
	for i := 0; i < params.polyExtendFactor; i++ {
		ctAccFourierDecomposed[i] = make([][]poly.FourierPoly, params.glweRank+1)
		for j := 0; j < params.glweRank+1; j++ {
			ctAccFourierDecomposed[i][j] = make([]poly.FourierPoly, params.bootstrapParameters.level)
			for k := 0; k < params.bootstrapParameters.level; k++ {
				ctAccFourierDecomposed[i][j][k] = poly.NewFourierPoly(params.polyDegree)
			}
		}
	}

	return evaluationBuffer[T]{
		fpMul:         poly.NewFourierPoly(params.polyDegree),
		ctFourierProd: NewFourierGLWECiphertext(params),
		ctCMux:        NewGLWECiphertext(params),

		ctAcc:                  ctAcc,
		ctFourierAcc:           ctFourierAcc,
		ctBlockFourierAcc:      ctBlockFourierAcc,
		ctAccFourierDecomposed: ctAccFourierDecomposed,
		fMono:                  poly.NewFourierPoly(params.polyDegree),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   NewLWECiphertextCustom[T](params.glweDimension),
		ctKeySwitch: NewLWECiphertextCustom[T](params.lweDimension),

		lut: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),
		Decomposer:      e.Decomposer.ShallowCopy(),

		Parameters: e.Parameters,

		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		modSwitchConstant: e.modSwitchConstant,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
