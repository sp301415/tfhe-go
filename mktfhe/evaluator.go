package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Evaluator is a multi-key variant of [tfhe.Evaluator].
type Evaluator[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this Evaluator.
	*tfhe.Encoder[T]
	// GLWETansformer is an embedded GLWETransformer for this Evaluator.
	*tfhe.GLWETransformer[T]
	// SingleKeyEvaluators are single-key Evaluators for this Evaluator.
	SingleKeyEvaluators []*tfhe.Evaluator[T]

	// Parameters is the parameters for the evaluator.
	Parameters Parameters[T]

	// EvaluationKeys are the evaluation key for this Evaluator.
	// This is shared with SingleKeyEvaluators.
	EvaluationKeys []EvaluationKey[T]

	// buffer is a buffer for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer is a buffer for evaluation.
type evaluationBuffer[T tfhe.TorusInt] struct {
	// ctProd holds the intermediate value in Hybrid Product.
	ctProd GLWECiphertext[T]
	// ctFourierProd holds the fourier transformed ctHybrid in Hybrid Product.
	ctFourierProd FourierGLWECiphertext[T]

	// ctProdSingle holds the intermediate single-key ciphertext in Hybrid Product.
	ctProdSingle poly.Poly[T]
	// ctFourierProdSingle holds the fourier transformed ctHybridSingle in Hybrid Product.
	ctFourierProdSingle poly.FourierPoly

	// ctRelin holds the intermediate value in Generalized External Product.
	ctRelin GLWECiphertext[T]
	// ctRelinTransposed is a transposed version of ctRelin.
	ctRelinTransposed []tfhe.GLWECiphertext[T]
}

// NewEvaluator allocates an empty Evaluator.
func NewEvaluator[T tfhe.TorusInt](params Parameters[T], evks []EvaluationKey[T]) *Evaluator[T] {
	if len(evks) != params.partyCount {
		panic("EvaluationKey length not equal to PartyCount")
	}

	evals := make([]*tfhe.Evaluator[T], len(evks))
	for i := range evks {
		evals[i] = tfhe.NewEvaluator(params.Parameters, evks[i].EvaluationKey)
	}

	return &Evaluator[T]{
		Encoder:             tfhe.NewEncoder(params.Parameters),
		GLWETransformer:     tfhe.NewGLWETransformer(params.Parameters),
		SingleKeyEvaluators: evals,

		Parameters: params,

		EvaluationKeys: evks,

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T tfhe.TorusInt](params Parameters[T]) evaluationBuffer[T] {
	ctRelin := NewGLWECiphertext(params)
	ctRelinTransposed := make([]tfhe.GLWECiphertext[T], params.GLWEDimension()+1)
	for i := 0; i < params.GLWEDimension()+1; i++ {
		ctRelinTransposed[i] = tfhe.NewGLWECiphertext(params.Parameters)
	}

	return evaluationBuffer[T]{
		ctProd:        NewGLWECiphertext(params),
		ctFourierProd: NewFourierGLWECiphertext(params),

		ctProdSingle:        poly.NewPoly[T](params.PolyDegree()),
		ctFourierProdSingle: poly.NewFourierPoly(params.PolyDegree()),

		ctRelin:           ctRelin,
		ctRelinTransposed: ctRelinTransposed,
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	evals := make([]*tfhe.Evaluator[T], len(e.SingleKeyEvaluators))
	for i, eval := range e.SingleKeyEvaluators {
		evals[i] = eval.ShallowCopy()
	}

	return &Evaluator[T]{
		Encoder:             e.Encoder,
		GLWETransformer:     e.GLWETransformer.ShallowCopy(),
		SingleKeyEvaluators: evals,

		Parameters: e.Parameters,

		EvaluationKeys: e.EvaluationKeys,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
