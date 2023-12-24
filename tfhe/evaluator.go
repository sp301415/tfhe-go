package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// Evaluator evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
type Evaluator[T Tint] struct {
	*Encoder[T]

	Parameters Parameters[T]

	PolyEvaluator    *poly.Evaluator[T]
	FourierEvaluator *poly.FourierEvaluator[T]

	EvaluationKey EvaluationKey[T]

	buffer evaluationBuffer[T]
}

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T Tint] struct {
	// polyDecomposed holds the decomposed polynomial.
	// Initially has length bootstrapParameters.level.
	// Use getPolyDecomposedBuffer() to get appropriate length of buffer.
	polyDecomposed []poly.Poly[T]
	// polyFourierDecomposed holds the decomposed polynomial in Fourier domain.
	// Initially has length bootstrapParameters.level.
	// Use getPolyFourierDecomposedBuffer() to get appropriate length of buffer.
	polyFourierDecomposed []poly.FourierPoly
	// decomposed holds the decomposed scalar.
	// Initially has length keyswitchParameters.level.
	// Use getDecomposedBuffer() to get appropriate length of buffer.
	decomposed []T

	// fpOut holds the fourier transformed polynomial for multiplications.
	fpOut poly.FourierPoly
	// ctFourierProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux holds ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// ctAcc holds the accumulator in Blind Rotation.
	// In case of BlindRotateBlock and BlindRotateOriginal, only the first element is used.
	// This has length PolyExpandFactor.
	ctAcc []GLWECiphertext[T]
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

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
}

// NewEvaluator creates a new Evaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluator[T Tint](params Parameters[T], evkey EvaluationKey[T]) *Evaluator[T] {
	return &Evaluator[T]{
		Encoder: NewEncoder(params),

		Parameters: params,

		PolyEvaluator:    poly.NewEvaluator[T](params.polyDegree),
		FourierEvaluator: poly.NewFourierEvaluator[T](params.polyDegree),

		EvaluationKey: evkey,

		buffer: newEvaluationBuffer(params),
	}
}

// NewEvaluatorWithoutKey creates a new Evaluator based on parameters, but without evaluation keys.
// This will panic if any operation that requires evaluation key is called.
func NewEvaluatorWithoutKey[T Tint](params Parameters[T]) *Evaluator[T] {
	return NewEvaluator[T](params, EvaluationKey[T]{})
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T Tint](params Parameters[T]) evaluationBuffer[T] {
	polyDecomposed := make([]poly.Poly[T], params.bootstrapParameters.level)
	for i := range polyDecomposed {
		polyDecomposed[i] = poly.NewPoly[T](params.polyDegree)
	}

	polyFourierDecomposed := make([]poly.FourierPoly, params.bootstrapParameters.level)
	for i := range polyFourierDecomposed {
		polyFourierDecomposed[i] = poly.NewFourierPoly(params.polyDegree)
	}

	ctAcc := make([]GLWECiphertext[T], params.PolyExtendFactor())
	for i := range ctAcc {
		ctAcc[i] = NewGLWECiphertext(params)
	}

	ctAccFourierDecomposed := make([][][]poly.FourierPoly, params.PolyExtendFactor()+1)
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

		ctAcc:                  ctAcc,
		ctAccFourierDecomposed: ctAccFourierDecomposed,
		fMono:                  poly.NewFourierPoly(params.polyDegree),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   NewLWECiphertextCustom[T](params.lweLargeDimension),
		ctKeySwitch: NewLWECiphertextCustom[T](params.lweDimension),

		lut: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		Encoder: e.Encoder,

		Parameters: e.Parameters,

		PolyEvaluator:    e.PolyEvaluator.ShallowCopy(),
		FourierEvaluator: e.FourierEvaluator.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
