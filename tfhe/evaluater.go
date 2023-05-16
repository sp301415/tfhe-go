package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// Evaluater evaluates homomorphic operations on ciphertexts.
// This is meant to be public for everyone.
//
// Evaluater uses fftw as backend, so manually freeing memory is needed.
// Use defer clause after initialization:
//
//	eval := tfhe.NewEvaluater(params, evkey)
//	defer eval.Free()
type Evaluater[T Tint] struct {
	Parameters Parameters[T]

	PolyEvaluater      poly.Evaluater[T]
	FourierTransformer poly.FourierTransformer[T]

	evaluationKey EvaluationKey[T]

	buffer evaluationBuffer[T]
}

const (
	MaxBufferDecomposedLevel = 10
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
	// rotatedCtForBlindRotate holds X^ai * ci in BlindRotate.
	rotatedCtForBlindRotate GLWECiphertext[T]

	// blindRotatedCtForBootstrap holds the blind rotated GLWE ciphertext for bootstrapping.
	blindRotatedCtForBootstrap GLWECiphertext[T]
	// sampleExtractedCtForBootstrap holds the sample extracted LWE large ciphertext for bootstrapping.
	sampleExtractedCtForBootstrap LWECiphertext[T]

	// addLWECtForMul holds ct0 + ct1 for LWE multiplication.
	addLWECtForMul LWECiphertext[T]
	// subLWECtForMul holds ct0 - ct1 for LWE multiplication.
	subLWECtForMul LWECiphertext[T]
	// twoLWECtForOps holds ct0 || ct1 for carry-based operations.
	twoLWECtForOps LWECiphertext[T]

	// idLUT is a LUT of identity function f: x -> x.
	idLUT LookUpTable[T]
	// mulLUT is a LUT of multiplication function f: x -> x^2/4.
	mulLUT LookUpTable[T]
	// emptyLUT is an empty LUT, used for BlindRotateFunc.
	emptyLUT LookUpTable[T]
}

// NewEvaluater creates a new Evaluater based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluater[T Tint](params Parameters[T], evkey EvaluationKey[T]) Evaluater[T] {
	evaluater := NewEvaluaterWithoutKey(params)
	evaluater.evaluationKey = EvaluationKey[T]{
		BootstrapKey: evkey.BootstrapKey,
		KeySwitchKey: evkey.KeySwitchKey,
	}

	return evaluater
}

// NewEvaluaterWithoutKey initializes a new Evaluater without keys.
// If you try to bootstrap without keys, it will panic.
// You can supply evaluation key later by using SetEvaluationKey().
func NewEvaluaterWithoutKey[T Tint](params Parameters[T]) Evaluater[T] {
	return Evaluater[T]{
		Parameters: params,

		PolyEvaluater:      poly.NewEvaluater[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T Tint](params Parameters[T]) evaluationBuffer[T] {
	decomposedPoly := make([]poly.Poly[T], MaxBufferDecomposedLevel)
	for i := range decomposedPoly {
		decomposedPoly[i] = poly.New[T](params.polyDegree)
	}

	idLUT := NewLookUpTable(params)
	genLookUpTableInPlace(params, func(x int) int { return x }, idLUT)

	mulLUT := NewLookUpTable(params)
	genLookUpTableInPlace(params, func(x int) int {
		mod := int(params.messageModulus)
		x %= mod
		if x > mod/2 {
			x = mod - x
		}
		return x * x / 4
	}, mulLUT)

	return evaluationBuffer[T]{
		decomposedPoly: decomposedPoly,
		decomposedVec:  make([]T, MaxBufferDecomposedLevel),

		fourierCtOutForExtProd: NewFourierGLWECiphertext(params),
		ctSubForCMux:           NewGLWECiphertext(params),

		rotatedCtForBlindRotate: NewGLWECiphertext(params),

		blindRotatedCtForBootstrap:    NewGLWECiphertext(params),
		sampleExtractedCtForBootstrap: NewLargeLWECiphertext(params),

		addLWECtForMul: NewLWECiphertext(params),
		subLWECtForMul: NewLWECiphertext(params),
		twoLWECtForOps: NewLWECiphertext(params),

		idLUT:    idLUT,
		mulLUT:   mulLUT,
		emptyLUT: NewLookUpTable(params),
	}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater[T]) ShallowCopy() Evaluater[T] {
	return Evaluater[T]{
		Parameters: e.Parameters,

		PolyEvaluater:      e.PolyEvaluater.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		evaluationKey: e.evaluationKey,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}

// Free frees internal fftw data.
func (e Evaluater[T]) Free() {
	e.FourierTransformer.Free()
}
