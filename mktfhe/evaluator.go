package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Evaluator is a multi-key variant of [tfhe.Evaluator].
type Evaluator[T tfhe.TorusInt] struct {
	// Encoder is an embedded Encoder for this Evaluator.
	*tfhe.Encoder[T]
	// GLWETansformer is an embedded GLWETransformer for this Evaluator.
	*tfhe.GLWETransformer[T]
	// BaseSingleKeyEvaluator is a single-key Evaluator for this Evaluator.
	// This is always guaranteed to be a working, non-nil evaluator without a key.
	BaseSingleKeyEvaluator *tfhe.Evaluator[T]
	// SingleKeyEvaluators are single-key Evaluators for this Evaluator.
	// If an evaluation key does not exist for given index, it is nil.
	SingleKeyEvaluators []*tfhe.Evaluator[T]

	// Parameters is the parameters for the evaluator.
	Parameters Parameters[T]

	// PartyBitMap is a bitmap for parties.
	// If a party of a given index exists, it is true.
	PartyBitMap []bool

	// EvaluationKeys are the evaluation key for this Evaluator.
	// This is shared with SingleKeyEvaluators.
	// If an evaluation key does not exist for given index, it is empty.
	EvaluationKeys []EvaluationKey[T]

	// buffer is a buffer for this Evaluator.
	buffer evaluationBuffer[T]
}

// evaluationBuffer is a buffer for evaluation.
type evaluationBuffer[T tfhe.TorusInt] struct {
	// polyFourierDecomposed holds the decomposed polynomial in Fourier domain.
	// Initially has length bootstrapParameters.level.
	// Use [*Evaluator.polyFourierDecomposedBuffer] to get appropriate length of buffer.
	polyFourierDecomposed []poly.FourierPoly
	// decomposed holds the decomposed scalar.
	// Initially has length keyswitchParameters.level.
	// Use [*Evaluator.decomposedBuffer] to get appropriate length of buffer.
	decomposed []T

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

	// ctRotateInputs holds the input of the Blind Rotation to each single evaluator.
	ctRotateInputs []tfhe.LWECiphertext[T]
	// gadgetLUTs holds the gadget LUT for the Blind Rotation.
	gadgetLUTs []tfhe.LookUpTable[T]
	// ctAccs holds the output of the accumulator of a single-key Blind Rotation.
	ctAccs []tfhe.GLWECiphertext[T]
	// ctFourierAccs holds the fourier transformed ctAccs.
	ctFourierAccs []tfhe.FourierGLevCiphertext[T]

	// ctRotate holds the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract holds the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitch holds LWEDimension sized ciphertext from keyswitching.
	ctKeySwitch LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewEvaluator allocates an empty Evaluator.
// Only indices between 0 and params.PartyCount is valid for evk.
func NewEvaluator[T tfhe.TorusInt](params Parameters[T], evk map[int]EvaluationKey[T]) *Evaluator[T] {
	evals := make([]*tfhe.Evaluator[T], params.PartyCount())
	evks := make([]EvaluationKey[T], params.PartyCount())
	partyBitMap := make([]bool, params.PartyCount())
	for i := range evk {
		evals[i] = tfhe.NewEvaluator(params.Parameters, evk[i].EvaluationKey)
		evks[i] = evk[i]
		partyBitMap[i] = true
	}

	return &Evaluator[T]{
		Encoder:                tfhe.NewEncoder(params.Parameters),
		GLWETransformer:        tfhe.NewGLWETransformer(params.Parameters),
		BaseSingleKeyEvaluator: tfhe.NewEvaluatorWithoutKey(params.Parameters),
		SingleKeyEvaluators:    evals,

		Parameters:  params,
		PartyBitMap: partyBitMap,

		EvaluationKeys: evks,

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer allocates an empty evaluationBuffer.
func newEvaluationBuffer[T tfhe.TorusInt](params Parameters[T]) evaluationBuffer[T] {
	polyFourierDecomposed := make([]poly.FourierPoly, params.relinKeyParameters.Level())
	for i := range polyFourierDecomposed {
		polyFourierDecomposed[i] = poly.NewFourierPoly(params.PolyDegree())
	}

	ctRelin := NewGLWECiphertext(params)
	ctRelinTransposed := make([]tfhe.GLWECiphertext[T], params.GLWEDimension()+1)
	for i := 0; i < params.GLWEDimension()+1; i++ {
		ctRelinTransposed[i] = tfhe.NewGLWECiphertext(params.Parameters)
	}

	ctRotateInputs := make([]tfhe.LWECiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctRotateInputs[i] = tfhe.NewLWECiphertext(params.Parameters)
	}

	gadgetLUTs := make([]tfhe.LookUpTable[T], params.accumulatorParameters.Level())
	for i := 0; i < params.accumulatorParameters.Level(); i++ {
		gadgetLUTs[i] = tfhe.NewLookUpTable(params.Parameters)
		gadgetLUTs[i].Coeffs[0] = params.accumulatorParameters.ScaledBase(i)
	}

	ctAccs := make([]tfhe.GLWECiphertext[T], params.partyCount)
	ctFourierAccs := make([]tfhe.FourierGLevCiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctAccs[i] = tfhe.NewGLWECiphertext(params.Parameters)
		ctFourierAccs[i] = tfhe.NewFourierGLevCiphertext(params.Parameters, params.accumulatorParameters)
	}

	return evaluationBuffer[T]{
		polyFourierDecomposed: polyFourierDecomposed,
		decomposed:            make([]T, params.KeySwitchParameters().Level()),

		ctProd:        NewGLWECiphertext(params),
		ctFourierProd: NewFourierGLWECiphertext(params),

		ctProdSingle:        poly.NewPoly[T](params.PolyDegree()),
		ctFourierProdSingle: poly.NewFourierPoly(params.PolyDegree()),

		ctRelin:           ctRelin,
		ctRelinTransposed: ctRelinTransposed,

		ctRotateInputs: ctRotateInputs,
		gadgetLUTs:     gadgetLUTs,
		ctAccs:         ctAccs,
		ctFourierAccs:  ctFourierAccs,

		ctRotate:    NewGLWECiphertext(params),
		ctExtract:   NewLWECiphertextCustom[T](params.LWELargeDimension()),
		ctKeySwitch: NewLWECiphertextCustom[T](params.LWEDimension()),

		lut: tfhe.NewLookUpTable(params.Parameters),
	}
}

// AddEvaluationKey adds an evaluation key for given index.
// If an evaluation key already exists for given index, it is overwritten.
func (e *Evaluator[T]) AddEvaluationKey(idx int, evk EvaluationKey[T]) {
	e.SingleKeyEvaluators[idx] = tfhe.NewEvaluator(e.Parameters.Parameters, evk.EvaluationKey)
	e.EvaluationKeys[idx] = evk
	e.PartyBitMap[idx] = true
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	evals := make([]*tfhe.Evaluator[T], e.Parameters.partyCount)
	for i, eval := range e.SingleKeyEvaluators {
		if eval != nil {
			evals[i] = eval.ShallowCopy()
		}
	}

	return &Evaluator[T]{
		Encoder:                e.Encoder,
		GLWETransformer:        e.GLWETransformer.ShallowCopy(),
		BaseSingleKeyEvaluator: e.BaseSingleKeyEvaluator.ShallowCopy(),
		SingleKeyEvaluators:    evals,

		Parameters:  e.Parameters,
		PartyBitMap: vec.Copy(e.PartyBitMap),

		EvaluationKeys: vec.Copy(e.EvaluationKeys),

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
