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

	// fpOut holds the fourier transformed polynomial for multiplications.
	fpOut poly.FourierPoly
	// ctFourierProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux holds ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// decomposedAcc holds the decomposed accumulator in Blind Rotation.
	decompsedAcc [][]poly.FourierPoly
	// localAcc holds the value of (ACC * BootstrapKey_i).
	localAcc GLWECiphertext[T]

	// ctRotate holds the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract holds the sample extracted LWE large ciphertext for bootstrapping.
	ctExtract LWECiphertext[T]
	// ctKeySwitch holds LargeLWEDimension - LWEDimension + 1 sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]

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

		fpOut:         poly.NewFourierPoly(params.polyDegree),
		ctFourierProd: NewFourierGLWECiphertext(params),
		ctCMux:        NewGLWECiphertext(params),

		decompsedAcc: decomposedAcc,
		localAcc:     NewGLWECiphertext(params),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()+1)},
		ctKeySwitch: LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()-params.lweDimension+1)},

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
