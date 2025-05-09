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
	*GLWETransformer[T]

	// BaseSingleKeyEvaluator is a single-key Evaluator for this Evaluator.
	// This is always guaranteed to be a working, non-nil evaluator without a key.
	BaseSingleKeyEvaluator *tfhe.Evaluator[T]
	// SingleKeyEvaluators are single-key Evaluators for this Evaluator.
	// If an evaluation key does not exist for given index, it is nil.
	SingleKeyEvaluators []*tfhe.Evaluator[T]

	// Decomposer is a Decomposer for this Evaluator.
	Decomposer *tfhe.Decomposer[T]
	// PolyEvaluator is a PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]

	// Parameters is the parameters for this Evaluator.
	Parameters Parameters[T]

	// PartyBitMap is a bitmap for parties.
	// If a party of a given index exists, it is true.
	PartyBitMap []bool

	// EvaluationKeys are the evaluation key for this Evaluator.
	// This is shared with SingleKeyEvaluators.
	// If an evaluation key does not exist for given index, it is empty.
	EvaluationKeys []EvaluationKey[T]

	// gadgetLUTs are the gadget LUT for the Blind Rotation.
	gadgetLUTs []tfhe.LookUpTable[T]

	buffer evaluationBuffer[T]
}

// evaluationBuffer is a buffer for evaluation.
type evaluationBuffer[T tfhe.TorusInt] struct {
	// ctProd is the intermediate value in Hybrid Product.
	ctProd GLWECiphertext[T]
	// ctFourierProd is the fourier transformed ctHybrid in Hybrid Product.
	ctFourierProd FourierGLWECiphertext[T]

	// ctProdSingle is the intermediate single-key ciphertext in Hybrid Product.
	ctProdSingle poly.Poly[T]
	// ctFourierProdSingle is the fourier transformed ctHybridSingle in Hybrid Product.
	ctFourierProdSingle poly.FourierPoly

	// ctRelin is the intermediate value in Generalized External Product.
	ctRelin GLWECiphertext[T]
	// ctRelinTransposed is a transposed version of ctRelin.
	ctRelinTransposed []tfhe.GLWECiphertext[T]

	// ctRotateInputs is the input of the Blind Rotation to each single evaluator.
	ctRotateInputs []tfhe.LWECiphertext[T]
	// ctAccs is the output of the accumulator of a single-key Blind Rotation.
	ctAccs []tfhe.GLWECiphertext[T]
	// ctFourierAccs is the fourier transformed ctAccs.
	ctFourierAccs []tfhe.FourierGLevCiphertext[T]

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitchForBootstrap is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitchForBootstrap LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewEvaluator creates a new Evaluator.
// Only indices between 0 and params.PartyCount is valid for evk.
func NewEvaluator[T tfhe.TorusInt](params Parameters[T], evk map[int]EvaluationKey[T]) *Evaluator[T] {
	singleEvals := make([]*tfhe.Evaluator[T], params.partyCount)
	singleKeys := make([]EvaluationKey[T], params.partyCount)
	partyBitMap := make([]bool, params.partyCount)
	for i := range evk {
		singleEvals[i] = tfhe.NewEvaluator(params.singleKeyParameters, evk[i].EvaluationKey)
		singleKeys[i] = evk[i]
		partyBitMap[i] = true
	}

	decomposer := tfhe.NewDecomposer[T](params.PolyDegree())
	decomposer.ScalarDecomposedBuffer(params.KeySwitchParameters())
	decomposer.PolyDecomposedBuffer(params.relinKeyParameters)
	decomposer.PolyFourierDecomposedBuffer(params.relinKeyParameters)

	gadgetLUTs := make([]tfhe.LookUpTable[T], params.accumulatorParameters.Level())
	for i := 0; i < params.accumulatorParameters.Level(); i++ {
		gadgetLUTs[i] = tfhe.NewLookUpTable(params.singleKeyParameters)
		gadgetLUTs[i].Value[0].Coeffs[0] = params.accumulatorParameters.BaseQ(i)
	}

	return &Evaluator[T]{
		Encoder:         tfhe.NewEncoder(params.singleKeyParameters),
		GLWETransformer: NewGLWETransformer[T](params.PolyDegree()),

		BaseSingleKeyEvaluator: tfhe.NewEvaluator(params.singleKeyParameters, tfhe.EvaluationKey[T]{}),
		SingleKeyEvaluators:    singleEvals,

		Decomposer:    decomposer,
		PolyEvaluator: poly.NewEvaluator[T](params.PolyDegree()),

		Parameters: params,

		PartyBitMap: partyBitMap,

		EvaluationKeys: singleKeys,

		gadgetLUTs: gadgetLUTs,

		buffer: newEvaluationBuffer(params),
	}
}

// newEvaluationBuffer creates a new evaluationBuffer.
func newEvaluationBuffer[T tfhe.TorusInt](params Parameters[T]) evaluationBuffer[T] {
	ctRelin := NewGLWECiphertext(params)
	ctRelinTransposed := make([]tfhe.GLWECiphertext[T], params.GLWERank()+1)
	for i := 0; i < params.GLWERank()+1; i++ {
		ctRelinTransposed[i] = tfhe.NewGLWECiphertext(params.singleKeyParameters)
	}

	ctRotateInputs := make([]tfhe.LWECiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctRotateInputs[i] = tfhe.NewLWECiphertextCustom[T](params.singleKeyParameters.LWEDimension())
	}

	ctAccs := make([]tfhe.GLWECiphertext[T], params.partyCount)
	ctFourierAccs := make([]tfhe.FourierGLevCiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctAccs[i] = tfhe.NewGLWECiphertext(params.singleKeyParameters)
		ctFourierAccs[i] = tfhe.NewFourierGLevCiphertext(params.singleKeyParameters, params.accumulatorParameters)
	}

	return evaluationBuffer[T]{
		ctProd:        NewGLWECiphertext(params),
		ctFourierProd: NewFourierGLWECiphertext(params),

		ctProdSingle:        poly.NewPoly[T](params.PolyDegree()),
		ctFourierProdSingle: poly.NewFourierPoly(params.PolyDegree()),

		ctRelin:           ctRelin,
		ctRelinTransposed: ctRelinTransposed,

		ctRotateInputs: ctRotateInputs,
		ctAccs:         ctAccs,
		ctFourierAccs:  ctFourierAccs,

		ctRotate:                NewGLWECiphertext(params),
		ctExtract:               NewLWECiphertextCustom[T](params.GLWEDimension()),
		ctKeySwitchForBootstrap: NewLWECiphertextCustom[T](params.LWEDimension()),

		lut: tfhe.NewLookUpTable(params.singleKeyParameters),
	}
}

// AddEvaluationKey adds an evaluation key for given index.
// If an evaluation key already exists for given index, it is overwritten.
func (e *Evaluator[T]) AddEvaluationKey(idx int, evk EvaluationKey[T]) {
	e.SingleKeyEvaluators[idx] = tfhe.NewEvaluator(e.Parameters.singleKeyParameters, evk.EvaluationKey)
	e.EvaluationKeys[idx] = evk
	e.PartyBitMap[idx] = true
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	singleEvals := make([]*tfhe.Evaluator[T], e.Parameters.partyCount)
	for i := range e.SingleKeyEvaluators {
		if e.SingleKeyEvaluators[i] != nil {
			singleEvals[i] = e.SingleKeyEvaluators[i].ShallowCopy()
		}
	}

	return &Evaluator[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		BaseSingleKeyEvaluator: e.BaseSingleKeyEvaluator.ShallowCopy(),
		SingleKeyEvaluators:    singleEvals,

		Decomposer:    e.Decomposer.ShallowCopy(),
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),

		Parameters:  e.Parameters,
		PartyBitMap: vec.Copy(e.PartyBitMap),

		EvaluationKeys: vec.Copy(e.EvaluationKeys),

		gadgetLUTs: e.gadgetLUTs,

		buffer: newEvaluationBuffer(e.Parameters),
	}
}
