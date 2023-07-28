package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// Evaluator evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
type Evaluator[T Tint] struct {
	Encoder[T]

	Parameters Parameters[T]

	PolyEvaluator      poly.Evaluator[T]
	FourierTransformer poly.FourierTransformer[T]

	EvaluationKey EvaluationKey[T]

	buffer evaluationBuffer[T]
}

const (
	// maxBufferDecomposedLevel represents the length of
	// initial buffer for decomposed values.
	// You can get buffer of appropriate length
	// by using decomposedVecBuffer() and decomposedPolyBuffer().
	maxBufferDecomposedLevel = 5
)

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T Tint] struct {
	// decomposedPoly holds the decomposed polynomial.
	// Initially has length MaxBufferDecomposedLevel.
	decomposedPoly []poly.Poly[T]
	// decomposedVec holds the decomposed scalar.
	// Initially has length MaxBufferDecomposedLevel.
	decomposedVec []T

	// fpForOps holds the fourier transformed polynomial for multiplications.
	fpForOps poly.FourierPoly
	// fourierCtForExtProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	fourierCtForExtProd FourierGLWECiphertext[T]
	// ctSubForCMux holds ct1 - ct0 in CMux.
	ctSubForCMux GLWECiphertext[T]

	// decomposedAcc holds the decomposed accumulator in Blind Rotation.
	decompsedAcc [][]poly.FourierPoly
	// localAcc holds the value of (ACC * BootstrapKey_i).
	localAcc GLWECiphertext[T]

	// blindRotatedCt holds the blind rotated GLWE ciphertext for bootstrapping.
	blindRotatedCt GLWECiphertext[T]
	// sampleExtractedCt holds the sample extracted LWE large ciphertext for bootstrapping.
	sampleExtractedCt LWECiphertext[T]
	// leftoverCt holds LargeLWEDimension - LWEDimension + 1 sized ciphertext from keyswitching.
	leftoverCt LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]
}

// NewEvaluator creates a new Evaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluator[T Tint](params Parameters[T], evkey EvaluationKey[T]) Evaluator[T] {
	return Evaluator[T]{
		Encoder: NewEncoder(params),

		Parameters: params,

		PolyEvaluator:      poly.NewEvaluator[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		EvaluationKey: evkey,

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T Tint](params Parameters[T]) evaluationBuffer[T] {
	decomposedPoly := make([]poly.Poly[T], maxBufferDecomposedLevel)
	for i := range decomposedPoly {
		decomposedPoly[i] = poly.New[T](params.polyDegree)
	}

	decomposedAcc := make([][]poly.FourierPoly, params.glweDimension+1)
	for i := range decomposedAcc {
		decomposedAcc[i] = make([]poly.FourierPoly, params.bootstrapParameters.level)
		for j := range decomposedAcc[i] {
			decomposedAcc[i][j] = poly.NewFourierPoly(params.polyDegree)
		}
	}

	return evaluationBuffer[T]{
		decomposedPoly: decomposedPoly,
		decomposedVec:  make([]T, maxBufferDecomposedLevel),

		fpForOps:            poly.NewFourierPoly(params.polyDegree),
		fourierCtForExtProd: NewFourierGLWECiphertext(params),
		ctSubForCMux:        NewGLWECiphertext(params),

		decompsedAcc: decomposedAcc,
		localAcc:     NewGLWECiphertext(params),

		blindRotatedCt:    NewGLWECiphertext(params),
		sampleExtractedCt: LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()+1)},
		leftoverCt:        LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()-params.lweDimension+1)},

		lut: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e Evaluator[T]) ShallowCopy() Evaluator[T] {
	return Evaluator[T]{
		Encoder: e.Encoder,

		Parameters: e.Parameters,

		PolyEvaluator:      e.PolyEvaluator.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
