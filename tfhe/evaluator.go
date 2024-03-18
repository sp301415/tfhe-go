package tfhe

import (
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
	// glweTransformer is an embedded glweTransformer for this Evaluator.
	*GLWETransformer[T]

	// Parameters holds the parameters for this Evaluator.
	Parameters Parameters[T]

	// PolyEvaluator holds the PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]
	// FourierEvaluator holds the FourierEvaluator for this Evaluator.
	FourierEvaluator *poly.FourierEvaluator[T]

	// EvaluationKey holds the evaluation key for this Evaluator.
	EvaluationKey EvaluationKey[T]

	// buffer holds the buffer values for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T TorusInt] struct {
	// polyDecomposed holds the decomposed polynomial.
	// Initially has length bootstrapParameters.level.
	// Use [*Evaluator.polyDecomposedBuffer] to get appropriate length of buffer.
	polyDecomposed []poly.Poly[T]
	// polyFourierDecomposed holds the decomposed polynomial in Fourier domain.
	// Initially has length bootstrapParameters.level.
	// Use [*Evaluator.polyFourierDecomposedBuffer] to get appropriate length of buffer.
	polyFourierDecomposed []poly.FourierPoly
	// decomposed holds the decomposed scalar.
	// Initially has length keyswitchParameters.level.
	// Use [*Evaluator.decomposedBuffer] to get appropriate length of buffer.
	decomposed []T

	// fpOut holds the fourier transformed polynomial for multiplications.
	fpOut poly.FourierPoly
	// ctFourierProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux holds ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// pAcc holds the accumulator in Blind Rotation.
	// Since we transform them on-the-fly, we only need a single polynomial.
	pAcc []poly.Poly[T]
	// ctFourierAcc holds the fourier transformed ctAcc in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExpandFactor.
	ctFourierAcc []FourierGLWECiphertext[T]
	// ctBlockFourierAcc holds the auxillary accumulator in Blind Rotation.
	ctBlockFourierAcc FourierGLWECiphertext[T]
	// ctAccFourierDecomposed holds the decomposed ctAcc in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExpandFactor + 1,
	// where the last element is used as an auxiliary buffer.
	ctAccFourierDecomposed [][][]poly.FourierPoly
	// fMono holds the fourier transformed monomial in Blind Rotation.
	fMono poly.FourierPoly

	// ctRotate holds the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract holds the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitch holds LWEDimension sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]

	// ctPadding holds the padding bit of a ciphertext.
	ctPadding LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
}

// NewEvaluator allocates an empty Evaluator based on parameters.
// This does not copy evaluation keys, since they may be large.
func NewEvaluator[T TorusInt](params Parameters[T], evk EvaluationKey[T]) *Evaluator[T] {
	return &Evaluator[T]{
		Encoder:         NewEncoder(params),
		GLWETransformer: NewGLWETransformer(params),

		Parameters: params,

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		EvaluationKey: evk,

		buffer: newEvaluationBuffer(params),
	}
}

// NewEvaluatorWithoutKey allocates an empty Evaluator based on parameters, but without evaluation keys.
// This will panic if any operation that requires evaluation key is called.
func NewEvaluatorWithoutKey[T TorusInt](params Parameters[T]) *Evaluator[T] {
	return NewEvaluator[T](params, EvaluationKey[T]{})
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T TorusInt](params Parameters[T]) evaluationBuffer[T] {
	polyDecomposed := make([]poly.Poly[T], params.bootstrapParameters.level)
	for i := range polyDecomposed {
		polyDecomposed[i] = poly.NewPoly[T](params.polyDegree)
	}

	polyFourierDecomposed := make([]poly.FourierPoly, params.bootstrapParameters.level)
	for i := range polyFourierDecomposed {
		polyFourierDecomposed[i] = poly.NewFourierPoly(params.polyDegree)
	}

	ctAcc := make([]poly.Poly[T], params.polyExtendFactor)
	ctFourierAcc := make([]FourierGLWECiphertext[T], params.polyExtendFactor)
	for i := range ctFourierAcc {
		ctFourierAcc[i] = NewFourierGLWECiphertext(params)
		ctAcc[i] = poly.NewPoly[T](params.polyDegree)
	}

	ctAccFourierDecomposed := make([][][]poly.FourierPoly, params.polyExtendFactor+1)
	for i := range ctAccFourierDecomposed {
		ctAccFourierDecomposed[i] = make([][]poly.FourierPoly, params.glweDimension+1)
		for j := range ctAccFourierDecomposed[i] {
			ctAccFourierDecomposed[i][j] = make([]poly.FourierPoly, params.bootstrapParameters.level)
			for k := range ctAccFourierDecomposed[i][j] {
				ctAccFourierDecomposed[i][j][k] = poly.NewFourierPoly(params.polyDegree)
			}
		}
	}

	return evaluationBuffer[T]{
		polyDecomposed:        polyDecomposed,
		polyFourierDecomposed: polyFourierDecomposed,
		decomposed:            make([]T, params.keyswitchParameters.level),

		fpOut:         poly.NewFourierPoly(params.polyDegree),
		ctFourierProd: NewFourierGLWECiphertext(params),
		ctCMux:        NewGLWECiphertext(params),

		pAcc:                   ctAcc,
		ctFourierAcc:           ctFourierAcc,
		ctBlockFourierAcc:      NewFourierGLWECiphertext(params),
		ctAccFourierDecomposed: ctAccFourierDecomposed,
		fMono:                  poly.NewFourierPoly(params.polyDegree),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   NewLWECiphertextCustom[T](params.lweLargeDimension),
		ctKeySwitch: NewLWECiphertextCustom[T](params.lweDimension),

		ctPadding: NewLWECiphertext(params),

		lut: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		Parameters: e.Parameters,

		PolyEvaluator:    e.PolyEvaluator.ShallowCopy(),
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
