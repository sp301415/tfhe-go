package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// Evaluater evaluates homomorphic operations on ciphertexts.
// This is meant to be public, usually for servers.
type Evaluater[T Tint] struct {
	Parameters Parameters[T]

	PolyEvaluater      poly.Evaluater[T]
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

// evaluationBuffer contains buffer values for Evaluater.
type evaluationBuffer[T Tint] struct {
	// decomposedPoly holds the decomposed polynomial.
	// Initially has length MaxBufferDecomposedLevel.
	decomposedPoly []poly.Poly[T]
	// decomposedVec holds the decomposed scalar.
	// Initially has length MaxBufferDecomposedLevel.
	decomposedVec []T

	// fourierCtOutForExtProd holds the fourier transformed ctGLWEOut in ExternalProductFourier.
	fourierCtOutForExtProd FourierGLWECiphertext[T]
	// ctSubForCMux holds ct1 - ct0 in CMux.
	ctSubForCMux GLWECiphertext[T]

	// decomposedAcc holds the decomposed accumulator in Blind Rotation.
	decompsedAcc [][]poly.FourierPoly
	// localAcc holds the value of (ACC * BootstrapKey_i).
	localAcc GLWECiphertext[T]

	// blindRotatedCtForBootstrap holds the blind rotated GLWE ciphertext for bootstrapping.
	blindRotatedCtForBootstrap GLWECiphertext[T]
	// sampleExtractedCtForBootstrap holds the sample extracted LWE large ciphertext for bootstrapping.
	sampleExtractedCtForBootstrap LWECiphertext[T]
	// ctLeftOver holds LargeLWEDimension - LWEDimension + 1 sized ciphertext from keyswitching.
	ctLeftOver LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut LookUpTable[T]

	// outForPublicFunctionalKeySwitch holds the output value of f in GLWE public functional keyswitching.
	outForPublicFunctionalKeySwitch poly.Poly[T]
	// fourierCtForPublicFunctionalKeySwitch holds the accumulater value for GLWE public functional keyswitching.
	fourierCtForPublicFunctionalKeySwitch FourierGLWECiphertext[T]

	// levelCtForCircuitBootstrap holds a bootstrapped leveled ciphertext in Circuit Bootstrapping.
	levelCtForCircuitBootstrap LWECiphertext[T]
}

// NewEvaluater creates a new Evaluater based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluater[T Tint](params Parameters[T], evkey EvaluationKey[T]) Evaluater[T] {
	return Evaluater[T]{
		Parameters: params,

		PolyEvaluater:      poly.NewEvaluater[T](params.polyDegree),
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

		fourierCtOutForExtProd: NewFourierGLWECiphertext(params),
		ctSubForCMux:           NewGLWECiphertext(params),

		decompsedAcc: decomposedAcc,
		localAcc:     NewGLWECiphertext(params),

		blindRotatedCtForBootstrap:    NewGLWECiphertext(params),
		sampleExtractedCtForBootstrap: LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()+1)},

		ctLeftOver: LWECiphertext[T]{Value: make([]T, params.LargeLWEDimension()-params.lweDimension+1)},

		lut: NewLookUpTable(params),

		outForPublicFunctionalKeySwitch:       poly.New[T](params.polyDegree),
		fourierCtForPublicFunctionalKeySwitch: NewFourierGLWECiphertext(params),

		levelCtForCircuitBootstrap: NewLWECiphertext(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		Parameters: e.Parameters,

		PolyEvaluater:      e.PolyEvaluater.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		EvaluationKey: e.EvaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
