package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// Evaluator evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
type Evaluator[T Tint] struct {
	*Encoder[T]

	Parameters Parameters[T]

	PolyEvaluator      *poly.Evaluator[T]
	FourierTransformer *poly.FourierTransformer[T]

	EvaluationKey EvaluationKey[T]

	buffer evaluationBuffer[T]
}

const (
	// maxBufferDecomposedLevel represents the length of
	// initial buffer for decomposed values.
	// You can get buffer of appropriate length
	// by using vecDecomposedBuffer() and polyDecomposedBuffer().
	maxBufferDecomposedLevel = 5
)

// evaluationBuffer contains buffer values for Evaluator.
type evaluationBuffer[T Tint] struct {
	// polyDecomposed holds the decomposed polynomial.
	// Initially has length MaxBufferDecomposedLevel.
	// Use polyDecomposed() to get appropriate length of buffer.
	polyDecomposed []poly.Poly[T]
	// vecDecomposed holds the decomposed scalar.
	// Initially has length MaxBufferDecomposedLevel.
	// Use vecDecomposed() to get appropriate length of buffer.
	vecDecomposed []T

	// fpOut holds the fourier transformed polynomial for multiplications.
	fpOut poly.FourierPoly
	// ctFourierProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	ctFourierProd FourierGLWECiphertext[T]
	// ctCMux holds ct1 - ct0 in CMux.
	ctCMux GLWECiphertext[T]

	// accDecomposed holds the decomposed accumulator in Blind Rotation.
	accDecomposed [][]poly.FourierPoly
	// acc holds the accumulator in Blind Rotation.
	acc GLWECiphertext[T]

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
func NewEvaluator[T Tint](params Parameters[T], evkey EvaluationKey[T]) *Evaluator[T] {
	return &Evaluator[T]{
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
	polyDecomposed := make([]poly.Poly[T], maxBufferDecomposedLevel)
	for i := range polyDecomposed {
		polyDecomposed[i] = poly.New[T](params.polyDegree)
	}

	accDecomposed := make([][]poly.FourierPoly, params.glweDimension+1)
	for i := range accDecomposed {
		accDecomposed[i] = make([]poly.FourierPoly, params.bootstrapParameters.level)
		for j := range accDecomposed[i] {
			accDecomposed[i][j] = poly.NewFourierPoly(params.polyDegree)
		}
	}

	return evaluationBuffer[T]{
		polyDecomposed: polyDecomposed,
		vecDecomposed:  make([]T, maxBufferDecomposedLevel),

		fpOut:         poly.NewFourierPoly(params.polyDegree),
		ctFourierProd: NewFourierGLWECiphertext(params),
		ctCMux:        NewGLWECiphertext(params),

		accDecomposed: accDecomposed,
		acc:           NewGLWECiphertext(params),

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()+1)},
		ctKeySwitch: LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()-params.lweDimension+1)},

		lut: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	return &Evaluator[T]{
		Encoder: e.Encoder,

		Parameters: e.Parameters,

		PolyEvaluator:      e.PolyEvaluator.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
