package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// Sanitizer wraps around [tfhe.Evaluator], and implements TFHE sanitization.
// For more details, see https://eprint.iacr.org/2025/216.
//
// Sanitizer is not safe for concurrent use.
// Use [*Sanitizer.SafeCopy] to get a safe copy.
type Sanitizer[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this Sanitizer.
	*tfhe.Evaluator[T]

	// Params is the parameters for this Sanitizer.
	Params SanitizationParameters[T]

	// PublicKey is the public key for this Sanitizer.
	PublicKey tfhe.PublicKey[T]

	// RoundedGaussianSampler is a Rounded Gaussian sampler for this Sanitizer.
	RoundedGaussianSampler *csprng.GaussianSampler[T]
	// LinEvalGaussianSampler is a Discrete Gaussian sampler for Randomized Linear Evaluation.
	LinEvalGaussianSampler [2]*CDTSampler[T]
	// RandGaussianSampler is a Discrete Gaussian sampler for Randomized Encryption.
	RandGaussianSampler *CDTSampler[T]

	buf sanitizerBuffer[T]
}

// sanitizerBuffer is a buffer for Sanitizer.
type sanitizerBuffer[T tfhe.TorusInt] struct {
	// pGaussian is a buffer for Gaussian polynomial.
	pGaussian poly.Poly[T]

	// ctRandGLWE is a buffer for GLWE ciphertext.
	ctRandGLWE tfhe.GLWECiphertext[T]
	// ctRandLWE is a buffer for LWE ciphertext.
	ctRandLWE tfhe.LWECiphertext[T]

	// ctReRand is the rerandomized LWE ciphertext for bootstrapping.
	ctReRand tfhe.LWECiphertext[T]
	// ctRotate is the blind rotated GLWE ciphertext for bootstrapping.
	ctRotate tfhe.GLWECiphertext[T]
	// ctKeySwitch is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitch tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewSanitizer creates a new Sanitizer.
func NewSanitizer[T tfhe.TorusInt](params SanitizationParameters[T], pk tfhe.PublicKey[T], evk tfhe.EvaluationKey[T]) *Sanitizer[T] {
	return &Sanitizer[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParams, evk),

		Params: params,

		PublicKey: pk,

		RoundedGaussianSampler: csprng.NewGaussianSampler[T](),
		LinEvalGaussianSampler: [2]*CDTSampler[T]{
			NewCDTSampler[T](0, params.LinEvalSigmaQ()),
			NewCDTSampler[T](-1/float64(2*params.baseParams.MessageModulus()), params.LinEvalSigmaQ()),
		},
		RandGaussianSampler: NewCDTSampler[T](0, params.RandSigmaQ()),

		buf: newSanitizerBuffer(params),
	}
}

// newSanitizerBuffer creates a new sanitizerBuffer.
func newSanitizerBuffer[T tfhe.TorusInt](params SanitizationParameters[T]) sanitizerBuffer[T] {
	return sanitizerBuffer[T]{
		pGaussian: poly.NewPoly[T](params.baseParams.PolyRank()),

		ctRandGLWE: tfhe.NewGLWECiphertext(params.baseParams),
		ctRandLWE:  tfhe.NewLWECiphertext(params.baseParams),

		ctReRand:    tfhe.NewLWECiphertextCustom[T](params.baseParams.GLWEDimension()),
		ctRotate:    tfhe.NewGLWECiphertext(params.baseParams),
		ctKeySwitch: tfhe.NewLWECiphertextCustom[T](params.baseParams.LWEDimension()),

		lut: tfhe.NewLUT(params.baseParams),
	}
}

// SafeCopy creates a shallow copy of this Sanitizer.
func (s *Sanitizer[T]) SafeCopy() *Sanitizer[T] {
	return &Sanitizer[T]{
		Evaluator: s.Evaluator.SafeCopy(),

		Params: s.Params,

		PublicKey: s.PublicKey,

		RoundedGaussianSampler: csprng.NewGaussianSampler[T](),
		LinEvalGaussianSampler: [2]*CDTSampler[T]{
			NewCDTSampler[T](s.LinEvalGaussianSampler[0].center, s.LinEvalGaussianSampler[0].stdDev),
			NewCDTSampler[T](s.LinEvalGaussianSampler[1].center, s.LinEvalGaussianSampler[1].stdDev),
		},
		RandGaussianSampler: NewCDTSampler[T](s.RandGaussianSampler.center, s.RandGaussianSampler.stdDev),

		buf: newSanitizerBuffer(s.Params),
	}
}

// ReRandGLWE rerandomizes the mask of the given GLWE ciphertext to uniform.
func (s *Sanitizer[T]) ReRandGLWETo(ctOut, ct tfhe.GLWECiphertext[T]) {
	ctOut.CopyFrom(ct)

	s.RandGaussianSampler.SamplePolyTo(s.buf.pGaussian)

	s.PolyEvaluator.MulPolyTo(s.buf.ctRandGLWE.Value[0], s.PublicKey.GLWEKey.Value[0].Value[0], s.buf.pGaussian)
	s.PolyEvaluator.MulPolyTo(s.buf.ctRandGLWE.Value[1], s.PublicKey.GLWEKey.Value[0].Value[1], s.buf.pGaussian)

	s.RandGaussianSampler.SamplePolyAddTo(s.buf.ctRandGLWE.Value[1])
	s.RoundedGaussianSampler.SamplePolyAddTo(s.buf.ctRandGLWE.Value[0], s.Params.RandTauQ())

	s.AddGLWETo(ctOut, ctOut, s.buf.ctRandGLWE)
}

// ReRandGLWE rerandomizes the mask of the given LWE ciphertext to uniform.
// Input and output ciphertexts should be of length GLWEDimension + 1.
func (s *Sanitizer[T]) ReRandLWETo(ctOut, ct tfhe.LWECiphertext[T]) {
	ctOut.CopyFrom(ct)

	s.RandGaussianSampler.SamplePolyTo(s.buf.pGaussian)

	s.PolyEvaluator.MulPolyTo(s.buf.ctRandGLWE.Value[0], s.PublicKey.GLWEKey.Value[0].Value[0], s.buf.pGaussian)
	s.PolyEvaluator.MulPolyTo(s.buf.ctRandGLWE.Value[1], s.PublicKey.GLWEKey.Value[0].Value[1], s.buf.pGaussian)

	s.RandGaussianSampler.SamplePolyAddTo(s.buf.ctRandGLWE.Value[1])
	s.buf.ctRandGLWE.AsLWECiphertextTo(0, s.buf.ctRandLWE)

	s.AddLWETo(ctOut, ctOut, s.buf.ctRandLWE)
	ctOut.Value[0] += s.RoundedGaussianSampler.Sample(s.Params.RandTauQ())
}

// SanitizeFunc returns a sanitized and bootstrapped LWE ciphertext with respect to given function.
func (s *Sanitizer[T]) SanitizeFunc(ct tfhe.LWECiphertext[T], f func(int) int) tfhe.LWECiphertext[T] {
	s.GenLUTTo(s.buf.lut, f)
	return s.SanitizeLUT(ct, s.buf.lut)
}

// SanitizeFuncTo sanitizes and bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (s *Sanitizer[T]) SanitizeFuncTo(ctOut, ct tfhe.LWECiphertext[T], f func(int) int) {
	s.GenLUTTo(s.buf.lut, f)
	s.SanitizeLUTTo(ctOut, ct, s.buf.lut)
}

// SanitizeLUT returns a sanitized and bootstrapped LWE ciphertext with respect to given LUT.
func (s *Sanitizer[T]) SanitizeLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.LWECiphertext[T] {
	ctOut := tfhe.NewLWECiphertext(s.Params.baseParams)
	s.SanitizeLUTTo(ctOut, ct, lut)
	return ctOut
}

// SanitizeLUTTo sanitizes and bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (s *Sanitizer[T]) SanitizeLUTTo(ctOut, ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	s.ReRandLWETo(s.buf.ctReRand, ct)
	reRandBody := s.buf.ctReRand.Value[0]
	s.buf.ctReRand.Value[0] = 0

	s.DefaultKeySwitchTo(s.buf.ctKeySwitch, s.buf.ctReRand)
	s.BlindRotateTo(s.buf.ctRotate, s.buf.ctKeySwitch, lut)

	s.buf.pGaussian.Coeffs[0] = s.LinEvalGaussianSampler[1].Sample()
	s.LinEvalGaussianSampler[0].SampleVecTo(s.buf.pGaussian.Coeffs[1:])
	s.PolyEvaluator.ScalarMulPolyTo(s.buf.pGaussian, s.buf.pGaussian, 2*s.Params.baseParams.MessageModulus())
	s.buf.pGaussian.Coeffs[0] += 1
	s.PolyEvaluator.MonomialMulPolyInPlace(s.buf.pGaussian, -s.ModSwitch(reRandBody))
	for i := 0; i < s.Params.baseParams.GLWERank()+1; i++ {
		s.PolyEvaluator.MulPolyTo(s.buf.ctRotate.Value[i], s.buf.ctRotate.Value[i], s.buf.pGaussian)
	}

	s.buf.ctRotate.AsLWECiphertextTo(0, ctOut)
	ctOut.Value[0] += s.RoundedGaussianSampler.Sample(s.Params.LinEvalTauQ())
}
