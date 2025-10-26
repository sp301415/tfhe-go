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

	// subEvaluator is a single-key Evaluator for this Evaluator.
	// This is always guaranteed to be a working, non-nil evaluator without a key.
	subEvaluator *tfhe.Evaluator[T]
	// SubEvaluators are single-key Evaluators for this Evaluator.
	// If an evaluation key does not exist for given index, it is nil.
	SubEvaluators []*tfhe.Evaluator[T]

	// Decomposer is a Decomposer for this Evaluator.
	Decomposer *tfhe.Decomposer[T]
	// PolyEvaluator is a PolyEvaluator for this Evaluator.
	PolyEvaluator *poly.Evaluator[T]

	// Params is the parameters for this Evaluator.
	Params Parameters[T]

	// PartyBitMap is a bitmap for parties.
	// If a party of a given index exists, it is true.
	PartyBitMap []bool

	// EvalKey are the evaluation key for this Evaluator.
	// This is shared with SingleKeyEvaluators.
	// If an evaluation key does not exist for given index, it is empty.
	EvalKey []EvaluationKey[T]

	// gadgetLUTs are the gadget LUT for the Blind Rotation.
	gadgetLUTs []tfhe.LookUpTable[T]

	buf evaluatorBuffer[T]
}

// evaluatorBuffer is a buffer for evaluation.
type evaluatorBuffer[T tfhe.TorusInt] struct {
	// ctProd is the intermediate value in Hybrid Product.
	ctProd GLWECiphertext[T]
	// fctProd is the fourier transformed ctHybrid in Hybrid Product.
	fctProd FFTGLWECiphertext[T]

	// sctProd is the intermediate single-key ciphertext in Hybrid Product.
	sctProd poly.Poly[T]
	// sfctProd is the fourier transformed ctHybridSingle in Hybrid Product.
	sfctProd poly.FFTPoly

	// ctRelin is the intermediate value in Generalized External Product.
	ctRelin GLWECiphertext[T]
	// ctRelinT is a transposed version of ctRelin.
	ctRelinT []tfhe.GLWECiphertext[T]

	// ctRotateIn is the input of the Blind Rotation to each single evaluator.
	ctRotateIn []tfhe.LWECiphertext[T]
	// ctAccs is the output of the accumulator of a single-key Blind Rotation.
	ctAccs []tfhe.GLWECiphertext[T]
	// fctAccs is the fourier transformed ctAccs.
	fctAccs []tfhe.FFTGLevCiphertext[T]

	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate GLWECiphertext[T]
	// ctExtract is the extracted LWE ciphertext after Blind Rotation.
	ctExtract LWECiphertext[T]
	// ctKeySwitc is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitc LWECiphertext[T]

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
		singleEvals[i] = tfhe.NewEvaluator(params.subParams, evk[i].EvaluationKey)
		singleKeys[i] = evk[i]
		partyBitMap[i] = true
	}

	decomposer := tfhe.NewDecomposer[T](params.PolyRank())
	decomposer.ScalarBuffer(params.KeySwitchParams())
	decomposer.PolyBuffer(params.relinKeyParams)
	decomposer.FFTPolyBuffer(params.relinKeyParams)

	gadgetLUTs := make([]tfhe.LookUpTable[T], params.accumulatorParams.Level())
	for i := 0; i < params.accumulatorParams.Level(); i++ {
		gadgetLUTs[i] = tfhe.NewLUT(params.subParams)
		gadgetLUTs[i].Value[0].Coeffs[0] = params.accumulatorParams.BaseQ(i)
	}

	return &Evaluator[T]{
		Encoder:         tfhe.NewEncoder(params.subParams),
		GLWETransformer: NewGLWETransformer[T](params.PolyRank()),

		subEvaluator:  tfhe.NewEvaluator(params.subParams, tfhe.EvaluationKey[T]{}),
		SubEvaluators: singleEvals,

		Decomposer:    decomposer,
		PolyEvaluator: poly.NewEvaluator[T](params.PolyRank()),

		Params: params,

		PartyBitMap: partyBitMap,

		EvalKey: singleKeys,

		gadgetLUTs: gadgetLUTs,

		buf: newEvaluatorBuffer(params),
	}
}

// newEvaluatorBuffer creates a new evaluatorBuffer.
func newEvaluatorBuffer[T tfhe.TorusInt](params Parameters[T]) evaluatorBuffer[T] {
	ctRelin := NewGLWECiphertext(params)
	ctRelinT := make([]tfhe.GLWECiphertext[T], params.GLWERank()+1)
	for i := 0; i < params.GLWERank()+1; i++ {
		ctRelinT[i] = tfhe.NewGLWECiphertext(params.subParams)
	}

	ctRotateIn := make([]tfhe.LWECiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctRotateIn[i] = tfhe.NewLWECiphertextCustom[T](params.subParams.LWEDimension())
	}

	ctAccs := make([]tfhe.GLWECiphertext[T], params.partyCount)
	fctAccs := make([]tfhe.FFTGLevCiphertext[T], params.partyCount)
	for i := 0; i < params.partyCount; i++ {
		ctAccs[i] = tfhe.NewGLWECiphertext(params.subParams)
		fctAccs[i] = tfhe.NewFFTGLevCiphertext(params.subParams, params.accumulatorParams)
	}

	return evaluatorBuffer[T]{
		ctProd:  NewGLWECiphertext(params),
		fctProd: NewFFTGLWECiphertext(params),

		sctProd:  poly.NewPoly[T](params.PolyRank()),
		sfctProd: poly.NewFFTPoly(params.PolyRank()),

		ctRelin:  ctRelin,
		ctRelinT: ctRelinT,

		ctRotateIn: ctRotateIn,
		ctAccs:     ctAccs,
		fctAccs:    fctAccs,

		ctRotate:   NewGLWECiphertext(params),
		ctExtract:  NewLWECiphertextCustom[T](params.GLWEDimension()),
		ctKeySwitc: NewLWECiphertextCustom[T](params.LWEDimension()),

		lut: tfhe.NewLUT(params.subParams),
	}
}

// AddEvaluationKey adds an evaluation key for given index.
// If an evaluation key already exists for given index, it is overwritten.
func (e *Evaluator[T]) AddEvaluationKey(idx int, evk EvaluationKey[T]) {
	e.SubEvaluators[idx] = tfhe.NewEvaluator(e.Params.subParams, evk.EvaluationKey)
	e.EvalKey[idx] = evk
	e.PartyBitMap[idx] = true
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator[T]) ShallowCopy() *Evaluator[T] {
	singleEvals := make([]*tfhe.Evaluator[T], e.Params.partyCount)
	for i := range e.SubEvaluators {
		if e.SubEvaluators[i] != nil {
			singleEvals[i] = e.SubEvaluators[i].ShallowCopy()
		}
	}

	return &Evaluator[T]{
		Encoder:         e.Encoder,
		GLWETransformer: e.GLWETransformer.ShallowCopy(),

		subEvaluator:  e.subEvaluator.ShallowCopy(),
		SubEvaluators: singleEvals,

		Decomposer:    e.Decomposer.ShallowCopy(),
		PolyEvaluator: e.PolyEvaluator.ShallowCopy(),

		Params:      e.Params,
		PartyBitMap: vec.Copy(e.PartyBitMap),

		EvalKey: vec.Copy(e.EvalKey),

		gadgetLUTs: e.gadgetLUTs,

		buf: newEvaluatorBuffer(e.Params),
	}
}
