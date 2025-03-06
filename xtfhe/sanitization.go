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
// Use [*Sanitizer.ShallowCopy] to get a safe copy.
type Sanitizer[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this Sanitizer.
	*tfhe.Evaluator[T]

	// Parameters is the parameters for this Sanitizer.
	Parameters SanitizationParameters[T]

	// PublicKey is the public key for this Sanitizer.
	PublicKey tfhe.PublicKey[T]

	// RoundedGaussianSampler is a Rounded Gaussian sampler for this Sanitizer.
	RoundedGaussianSampler *csprng.GaussianSampler[T]
	// LinEvalGaussianSampler is a Discrete Gaussian sampler for Randomized Linear Evaluation.
	LinEvalGaussianSampler [2]*CDTSampler[T]
	// RandGaussianSampler is a Discrete Gaussian sampler for Randomized Encryption.
	RandGaussianSampler *CDTSampler[T]

	buffer sanitizationBuffer[T]
}

// sanitizationBuffer is a buffer for Sanitizer.
type sanitizationBuffer[T tfhe.TorusInt] struct {
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
	// ctKeySwitchForBootstrap is the LWEDimension sized ciphertext from keyswitching for bootstrapping.
	ctKeySwitchForBootstrap tfhe.LWECiphertext[T]

	// lut is an empty lut, used for BlindRotateFunc.
	lut tfhe.LookUpTable[T]
}

// NewSanitizer creates a new Sanitizer.
func NewSanitizer[T tfhe.TorusInt](params SanitizationParameters[T], pk tfhe.PublicKey[T], evk tfhe.EvaluationKey[T]) *Sanitizer[T] {
	return &Sanitizer[T]{
		Evaluator: tfhe.NewEvaluator(params.baseParameters, evk),

		Parameters: params,

		PublicKey: pk,

		RoundedGaussianSampler: csprng.NewGaussianSampler[T](),
		LinEvalGaussianSampler: [2]*CDTSampler[T]{
			NewCDTSampler[T](0, params.LinEvalSigmaQ()),
			NewCDTSampler[T](-1/float64(2*params.baseParameters.MessageModulus()), params.LinEvalSigmaQ()),
		},
		RandGaussianSampler: NewCDTSampler[T](0, params.RandSigmaQ()),

		buffer: newSanitizationBuffer[T](params),
	}
}

// newSanitizationBuffer creates a new sanitizationBuffer.
func newSanitizationBuffer[T tfhe.TorusInt](params SanitizationParameters[T]) sanitizationBuffer[T] {
	return sanitizationBuffer[T]{
		pGaussian: poly.NewPoly[T](params.baseParameters.PolyDegree()),

		ctRandGLWE: tfhe.NewGLWECiphertext(params.baseParameters),
		ctRandLWE:  tfhe.NewLWECiphertext(params.baseParameters),

		ctReRand:                tfhe.NewLWECiphertextCustom[T](params.baseParameters.GLWEDimension()),
		ctRotate:                tfhe.NewGLWECiphertext(params.baseParameters),
		ctKeySwitchForBootstrap: tfhe.NewLWECiphertextCustom[T](params.baseParameters.LWEDimension()),

		lut: tfhe.NewLookUpTable(params.baseParameters),
	}
}

// ShallowCopy creates a shallow copy of this Sanitizer.
func (s *Sanitizer[T]) ShallowCopy() *Sanitizer[T] {
	return &Sanitizer[T]{
		Evaluator: s.Evaluator.ShallowCopy(),

		Parameters: s.Parameters,

		PublicKey: s.PublicKey,

		RoundedGaussianSampler: csprng.NewGaussianSampler[T](),
		LinEvalGaussianSampler: [2]*CDTSampler[T]{
			NewCDTSampler[T](s.LinEvalGaussianSampler[0].center, s.LinEvalGaussianSampler[0].stdDev),
			NewCDTSampler[T](s.LinEvalGaussianSampler[1].center, s.LinEvalGaussianSampler[1].stdDev),
		},
		RandGaussianSampler: NewCDTSampler[T](s.RandGaussianSampler.center, s.RandGaussianSampler.stdDev),

		buffer: newSanitizationBuffer[T](s.Parameters),
	}
}

// ReRandGLWE rerandomizes the mask of the given GLWE ciphertext to uniform.
func (s *Sanitizer[T]) ReRandGLWEAssign(ct, ctOut tfhe.GLWECiphertext[T]) {
	ctOut.CopyFrom(ct)

	s.RandGaussianSampler.SamplePolyAssign(s.buffer.pGaussian)

	s.PolyEvaluator.MulPolyAssign(s.PublicKey.GLWEKey.Value[0].Value[0], s.buffer.pGaussian, s.buffer.ctRandGLWE.Value[0])
	s.PolyEvaluator.MulPolyAssign(s.PublicKey.GLWEKey.Value[0].Value[1], s.buffer.pGaussian, s.buffer.ctRandGLWE.Value[1])

	s.RandGaussianSampler.SamplePolyAddAssign(s.buffer.ctRandGLWE.Value[1])
	s.RoundedGaussianSampler.SamplePolyAddAssign(s.Parameters.RandTauQ(), s.buffer.ctRandGLWE.Value[0])

	s.AddGLWEAssign(s.buffer.ctRandGLWE, ctOut, ctOut)
}

// ReRandGLWE rerandomizes the mask of the given LWE ciphertext to uniform.
// Input and output ciphertexts should be of length GLWEDimension + 1.
func (s *Sanitizer[T]) ReRandLWEAssign(ct, ctOut tfhe.LWECiphertext[T]) {
	ctOut.CopyFrom(ct)

	s.RandGaussianSampler.SamplePolyAssign(s.buffer.pGaussian)

	s.PolyEvaluator.MulPolyAssign(s.PublicKey.GLWEKey.Value[0].Value[0], s.buffer.pGaussian, s.buffer.ctRandGLWE.Value[0])
	s.PolyEvaluator.MulPolyAssign(s.PublicKey.GLWEKey.Value[0].Value[1], s.buffer.pGaussian, s.buffer.ctRandGLWE.Value[1])

	s.RandGaussianSampler.SamplePolyAddAssign(s.buffer.ctRandGLWE.Value[1])
	s.buffer.ctRandGLWE.ToLWECiphertextAssign(0, s.buffer.ctRandLWE)

	s.AddLWEAssign(s.buffer.ctRandLWE, ctOut, ctOut)
	ctOut.Value[0] += s.RoundedGaussianSampler.Sample(s.Parameters.RandTauQ())
}

// SanitizeFunc returns a sanitized and bootstrapped LWE ciphertext with respect to given function.
func (s *Sanitizer[T]) SanitizeFunc(ct tfhe.LWECiphertext[T], f func(int) int) tfhe.LWECiphertext[T] {
	s.GenLookUpTableAssign(f, s.buffer.lut)
	return s.SanitizeLUT(ct, s.buffer.lut)
}

// SanitizeFuncAssign sanitizes and bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (s *Sanitizer[T]) SanitizeFuncAssign(ct tfhe.LWECiphertext[T], f func(int) int, ctOut tfhe.LWECiphertext[T]) {
	s.GenLookUpTableAssign(f, s.buffer.lut)
	s.SanitizeLUTAssign(ct, s.buffer.lut, ctOut)
}

// SanitizeLUT returns a sanitized and bootstrapped LWE ciphertext with respect to given LUT.
func (s *Sanitizer[T]) SanitizeLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.LWECiphertext[T] {
	ctOut := tfhe.NewLWECiphertext(s.Parameters.baseParameters)
	s.SanitizeLUTAssign(ct, lut, ctOut)
	return ctOut
}

// SanitizeLUTAssign sanitizes and bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (s *Sanitizer[T]) SanitizeLUTAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.LWECiphertext[T]) {
	s.ReRandLWEAssign(ct, s.buffer.ctReRand)
	reRandBody := s.buffer.ctReRand.Value[0]
	s.buffer.ctReRand.Value[0] = 0

	s.KeySwitchForBootstrapAssign(s.buffer.ctReRand, s.buffer.ctKeySwitchForBootstrap)
	s.BlindRotateAssign(s.buffer.ctKeySwitchForBootstrap, lut, s.buffer.ctRotate)

	s.buffer.pGaussian.Coeffs[0] = s.LinEvalGaussianSampler[1].Sample()
	s.LinEvalGaussianSampler[0].SampleVecAssign(s.buffer.pGaussian.Coeffs[1:])
	s.PolyEvaluator.ScalarMulPolyAssign(s.buffer.pGaussian, 2*s.Parameters.baseParameters.MessageModulus(), s.buffer.pGaussian)
	s.buffer.pGaussian.Coeffs[0] += 1
	s.PolyEvaluator.MonomialMulPolyInPlace(s.buffer.pGaussian, -s.ModSwitch(reRandBody))
	for i := 0; i < s.Parameters.baseParameters.GLWERank()+1; i++ {
		s.PolyEvaluator.MulPolyAssign(s.buffer.ctRotate.Value[i], s.buffer.pGaussian, s.buffer.ctRotate.Value[i])
	}

	s.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	ctOut.Value[0] += s.RoundedGaussianSampler.Sample(s.Parameters.LinEvalTauQ())
}
