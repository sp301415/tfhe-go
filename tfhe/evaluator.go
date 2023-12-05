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

	// accDecomposed holds the decomposed accumulator in Blind Rotation.
	accDecomposed [][]poly.FourierPoly
	// acc holds the accumulator in Blind Rotation.
	acc GLWECiphertext[T]

	// ctKeySwitch holds LWEDimension - LWESmallDimension + 1 sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]
	// ctSmall holds LWESmallDimension sized ciphertext from keyswitching.
	ctSmall LWECiphertext[T]
	// ctRotate holds the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]

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

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T Tint](params Parameters[T]) evaluationBuffer[T] {
	polyDecomposed := make([]poly.Poly[T], params.bootstrapParameters.level)
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
		decomposed:     make([]T, params.keyswitchParameters.level),

		fpOut:         poly.NewFourierPoly(params.polyDegree),
		ctFourierProd: NewFourierGLWECiphertext(params),
		ctCMux:        NewGLWECiphertext(params),

		accDecomposed: accDecomposed,
		acc:           NewGLWECiphertext(params),

		ctKeySwitch: NewLWECiphertextCustom[T](params.lweDimension - params.lweSmallDimension),
		ctSmall:     NewLWECiphertextCustom[T](params.lweSmallDimension),
		ctRotate:    NewGLWECiphertext(params),

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
