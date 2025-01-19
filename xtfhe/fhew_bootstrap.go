package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *FHEWEvaluator[T]) BootstrapFunc(ct tfhe.LWECiphertext[T], f func(int) int) tfhe.LWECiphertext[T] {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *FHEWEvaluator[T]) BootstrapFuncAssign(ct tfhe.LWECiphertext[T], f func(int) int, ctOut tfhe.LWECiphertext[T]) {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *FHEWEvaluator[T]) BootstrapLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.LWECiphertext[T] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters.baseParameters)
	e.BootstrapLUTAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *FHEWEvaluator[T]) BootstrapLUTAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.LWECiphertext[T]) {
	switch e.Parameters.baseParameters.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitchForBootstrap)
		e.BlindRotateAssign(e.buffer.ctKeySwitchForBootstrap, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LookUpTableSize.
func (e *FHEWEvaluator[T]) ModSwitch(x T) int {
	return e.Evaluator.ModSwitch(x) | 1
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *FHEWEvaluator[T]) BlindRotate(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters.baseParameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *FHEWEvaluator[T]) BlindRotateAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(e.Parameters.baseParameters.BlindRotateParameters())

	ctAutIdxMap := make(map[int][]int)
	for i := 0; i < e.Parameters.baseParameters.LWEDimension(); i++ {
		a2N := e.ModSwitch(-ct.Value[i+1])
		a2NAutIdx := e.autIdxMap[a2N]
		ctAutIdxMap[a2NAutIdx] = append(ctAutIdxMap[a2NAutIdx], i)
	}

	e.PolyEvaluator.PermutePolyAssign(poly.Poly[T]{Coeffs: lut.Value}, -5, ctOut.Value[0])
	e.PolyEvaluator.MonomialMulPolyInPlace(ctOut.Value[0], -5*e.ModSwitch(-ct.Value[0]))
	for i := 1; i < e.Parameters.baseParameters.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	var nSkip int
	for i := e.Parameters.baseParameters.PolyDegree()/2 - 1; i > 0; i-- {
		if _, ok := ctAutIdxMap[-i]; ok {
			if nSkip != 0 {
				e.PermuteGLWEAssign(ctOut, num.ModExp(5, nSkip, 2*e.Parameters.baseParameters.PolyDegree()), e.buffer.ctPermute)
				e.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKey[nSkip], ctOut)
				nSkip = 0
			}

			for _, j := range ctAutIdxMap[-i] {
				for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
					e.Decomposer.DecomposePolyAssign(ctOut.Value[k], e.Parameters.baseParameters.BlindRotateParameters(), polyDecomposed)
					for l := 0; l < e.Parameters.baseParameters.BlindRotateParameters().Level(); l++ {
						e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[k][l])
					}
				}

				e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed, e.buffer.ctFourierAcc)
				for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
					e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc.Value[k], ctOut.Value[k])
				}
			}
		}
		nSkip++

		if nSkip == e.Parameters.windowSize || i == 1 {
			e.PermuteGLWEAssign(ctOut, num.ModExp(5, nSkip, 2*e.Parameters.baseParameters.PolyDegree()), e.buffer.ctPermute)
			e.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKey[nSkip], ctOut)
			nSkip = 0
		}
	}

	if _, ok := ctAutIdxMap[2*e.Parameters.baseParameters.PolyDegree()]; ok {
		for _, j := range ctAutIdxMap[2*e.Parameters.baseParameters.PolyDegree()] {
			for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyAssign(ctOut.Value[k], e.Parameters.baseParameters.BlindRotateParameters(), polyDecomposed)
				for l := 0; l < e.Parameters.baseParameters.BlindRotateParameters().Level(); l++ {
					e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[k][l])
				}
			}

			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed, e.buffer.ctFourierAcc)
			for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
				e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc.Value[k], ctOut.Value[k])
			}
		}
	}

	e.PermuteGLWEAssign(ctOut, -5, e.buffer.ctPermute)
	e.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKey[nSkip], ctOut)

	for i := e.Parameters.baseParameters.PolyDegree()/2 - 1; i > 0; i-- {
		if _, ok := ctAutIdxMap[i]; ok {
			if nSkip != 0 {
				e.PermuteGLWEAssign(ctOut, num.ModExp(5, nSkip, 2*e.Parameters.baseParameters.PolyDegree()), e.buffer.ctPermute)
				e.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKey[nSkip], ctOut)
				nSkip = 0
			}

			for _, j := range ctAutIdxMap[i] {
				for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
					e.Decomposer.DecomposePolyAssign(ctOut.Value[k], e.Parameters.baseParameters.BlindRotateParameters(), polyDecomposed)
					for l := 0; l < e.Parameters.baseParameters.BlindRotateParameters().Level(); l++ {
						e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[k][l])
					}
				}

				e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed, e.buffer.ctFourierAcc)
				for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
					e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc.Value[k], ctOut.Value[k])
				}
			}
		}
		nSkip++

		if nSkip == e.Parameters.windowSize || i == 1 {
			e.PermuteGLWEAssign(ctOut, num.ModExp(5, nSkip, 2*e.Parameters.baseParameters.PolyDegree()), e.buffer.ctPermute)
			e.KeySwitchGLWEAssign(e.buffer.ctPermute, e.EvaluationKey.GaloisKey[nSkip], ctOut)
			nSkip = 0
		}
	}

	if _, ok := ctAutIdxMap[0]; ok {
		for _, j := range ctAutIdxMap[0] {
			for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyAssign(ctOut.Value[k], e.Parameters.baseParameters.BlindRotateParameters(), polyDecomposed)
				for l := 0; l < e.Parameters.baseParameters.BlindRotateParameters().Level(); l++ {
					e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[k][l])
				}
			}

			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed, e.buffer.ctFourierAcc)
			for k := 0; k < e.Parameters.baseParameters.GLWERank()+1; k++ {
				e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc.Value[k], ctOut.Value[k])
			}
		}
	}
}
