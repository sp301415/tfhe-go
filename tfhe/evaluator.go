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

	// Parameters holds the parameters for this Evaluator.
	Parameters Parameters[T]

	// PolyEvaluator holds the PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]

	// EvaluationKey holds the evaluation key for this Evaluator.
	EvaluationKey EvaluationKey[T]

	// modSwitchConstant is a constant for modulus switching.
	modSwitchConstant float64

	// buffer holds the buffer values for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T TorusInt] struct {
	// decomposed holds the decomposed scalar.
	// Initially has length keyswitchParameters.level.
	// Use [*Evaluator.decomposedBuffer] to get appropriate length of buffer.
	decomposed []T
	// polyDecomposed holds the decomposed polynomial.
	// Initially has length bootstrapParameters.level.
	// Use [*Evaluator.polyDecomposedBuffer] to get appropriate length of buffer.
	polyDecomposed []poly.Poly[T]
	// polyFourierDecomposed holds the decomposed polynomial in Fourier domain.
	// Initially has length bootstrapParameters.level.
	// Use [*Evaluator.polyFourierDecomposedBuffer] to get appropriate length of buffer.
	polyFourierDecomposed []poly.FourierPoly

	// fpMul holds the fourier transformed polynomial for multiplications.
	fpMul poly.FourierPoly
	// ctFourierProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux holds ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// ctAcc holds the accumulator in BlindRotateExtended.
	// This has length PolyExtendFactor.
	ctAcc []GLWECiphertext[T]
	// ctFourierAcc holds the fourier transformed accumulator in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExtendFactor.
	ctFourierAcc []FourierGLWECiphertext[T]
	// ctBlockFourierAcc holds the auxiliary accumulator in BlindRotateBlock and BlindRotateExtended.
	ctBlockFourierAcc []FourierGLWECiphertext[T]
	// ctAccFourierDecomposed holds the decomposed ctAcc in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExpandFactor.
	ctAccFourierDecomposed [][][]poly.FourierPoly
	// fMono holds the fourier transformed monomial in Blind Rotation.
	fMono poly.FourierPoly

	// ctRotate holds the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract holds the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitch holds LWEDimension sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
}

// NewEvaluator allocates an empty Evaluator based on parameters.
// This does not copy evaluation keys, since they may be large.
func NewEvaluator[T TorusInt](params Parameters[T], evk EvaluationKey[T]) *Evaluator[T] {
	return &Evaluator[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer(params),
		Decomposer:      NewDecomposer[T](params.polyDegree),

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
		decomposed:            make([]T, params.keyswitchParameters.level),
		polyDecomposed:        polyDecomposed,
		polyFourierDecomposed: polyFourierDecomposed,

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
		Decomposer:      e.Decomposer,

		Parameters: e.Parameters,

		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		modSwitchConstant: e.modSwitchConstant,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}

// decomposedBuffer returns the decomposed buffer of Evaluator.
// if len(decomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) decomposedBuffer(gadgetParams GadgetParameters[T]) []T {
	if len(e.buffer.decomposed) >= gadgetParams.level {
		return e.buffer.decomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.decomposed)
	e.buffer.decomposed = append(e.buffer.decomposed, make([]T, gadgetParams.level-oldLen)...)
	return e.buffer.decomposed
}

// polyDecomposedBuffer returns the polyDecomposed buffer of Evaluator.
// if len(polyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) polyDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	if len(e.buffer.polyDecomposed) >= gadgetParams.level {
		return e.buffer.polyDecomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.polyDecomposed)
	e.buffer.polyDecomposed = append(e.buffer.polyDecomposed, make([]poly.Poly[T], gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		e.buffer.polyDecomposed[i] = e.PolyEvaluator.NewPoly()
	}
	return e.buffer.polyDecomposed
}

// polyFourierDecomposedBuffer returns the fourierPolyDecomposed buffer of Evaluator.
// if len(fourierPolyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) polyFourierDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.FourierPoly {
	if len(e.buffer.polyFourierDecomposed) >= gadgetParams.level {
		return e.buffer.polyFourierDecomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.polyFourierDecomposed)
	e.buffer.polyFourierDecomposed = append(e.buffer.polyFourierDecomposed, make([]poly.FourierPoly, gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		e.buffer.polyFourierDecomposed[i] = e.PolyEvaluator.NewFourierPoly()
	}
	return e.buffer.polyFourierDecomposed
}
