package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *FHEWEvaluator[T]) BootstrapFunc(ct tfhe.LWECiphertext[T], f func(int) int) tfhe.LWECiphertext[T] {
	e.GenLUTTo(e.buf.lut, f)
	return e.BootstrapLUT(ct, e.buf.lut)
}

// BootstrapFuncTo bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *FHEWEvaluator[T]) BootstrapFuncTo(ctOut tfhe.LWECiphertext[T], ct tfhe.LWECiphertext[T], f func(int) int) {
	e.GenLUTTo(e.buf.lut, f)
	e.BootstrapLUTTo(ctOut, ct, e.buf.lut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *FHEWEvaluator[T]) BootstrapLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.LWECiphertext[T] {
	ctOut := tfhe.NewLWECiphertext(e.Params.baseParams)
	e.BootstrapLUTTo(ctOut, ct, lut)
	return ctOut
}

// BootstrapLUTTo bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *FHEWEvaluator[T]) BootstrapLUTTo(ctOut tfhe.LWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	switch e.Params.baseParams.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.DefaultKeySwitchTo(e.buf.ctKeySwitch, ct)
		e.BlindRotateTo(e.buf.ctRotate, e.buf.ctKeySwitch, lut)
		e.buf.ctRotate.AsLWECiphertextTo(0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateTo(e.buf.ctRotate, ct, lut)
		e.buf.ctRotate.AsLWECiphertextTo(0, e.buf.ctExtract)
		e.DefaultKeySwitchTo(ctOut, e.buf.ctExtract)
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LUTSize.
func (e *FHEWEvaluator[T]) ModSwitch(x T) int {
	return e.Evaluator.ModSwitch(x) | 1
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *FHEWEvaluator[T]) BlindRotate(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params.baseParams)
	e.BlindRotateTo(ctOut, ct, lut)
	return ctOut
}

// BlindRotateTo computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *FHEWEvaluator[T]) BlindRotateTo(ctOut tfhe.GLWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	pDcmp := e.Decomposer.PolyBuffer(e.Params.baseParams.BlindRotateParams())

	ctAutIdxMap := make(map[int][]int, e.Params.baseParams.PolyRank())
	for i := 0; i < e.Params.baseParams.LWEDimension(); i++ {
		a2N := e.ModSwitch(-ct.Value[i+1])
		a2NAutIdx := e.autIdxMap[a2N]
		ctAutIdxMap[a2NAutIdx] = append(ctAutIdxMap[a2NAutIdx], i)
	}

	e.PolyEvaluator.PermutePolyTo(ctOut.Value[0], lut.Value[0], -5)
	e.PolyEvaluator.MonomialMulPolyInPlace(ctOut.Value[0], -5*e.ModSwitch(-ct.Value[0]))
	for i := 1; i < e.Params.baseParams.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	var skipCnt int
	for i := e.Params.baseParams.PolyRank()/2 - 1; i > 0; i-- {
		if _, ok := ctAutIdxMap[-i]; ok {
			if skipCnt != 0 {
				e.PermuteGLWETo(e.buf.ctPermute, ctOut, num.ModExp(5, skipCnt, 2*e.Params.baseParams.PolyRank()))
				e.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKey[skipCnt])
				skipCnt = 0
			}

			for _, j := range ctAutIdxMap[-i] {
				for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
					e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[k], e.Params.baseParams.BlindRotateParams())
					for l := 0; l < e.Params.baseParams.BlindRotateParams().Level(); l++ {
						e.PolyEvaluator.FFTTo(e.buf.ctFFTAccDcmp[k][l], pDcmp[l])
					}
				}

				e.ExternalProdFFTGLWETo(e.buf.ctFFTAcc, e.EvalKey.BlindRotateKey.Value[j], e.buf.ctFFTAccDcmp)
				for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
					e.PolyEvaluator.InvFFTToUnsafe(ctOut.Value[k], e.buf.ctFFTAcc.Value[k])
				}
			}
		}
		skipCnt++

		if skipCnt == e.Params.windowSize || i == 1 {
			e.PermuteGLWETo(e.buf.ctPermute, ctOut, num.ModExp(5, skipCnt, 2*e.Params.baseParams.PolyRank()))
			e.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKey[skipCnt])
			skipCnt = 0
		}
	}

	if _, ok := ctAutIdxMap[2*e.Params.baseParams.PolyRank()]; ok {
		for _, j := range ctAutIdxMap[2*e.Params.baseParams.PolyRank()] {
			for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[k], e.Params.baseParams.BlindRotateParams())
				for l := 0; l < e.Params.baseParams.BlindRotateParams().Level(); l++ {
					e.PolyEvaluator.FFTTo(e.buf.ctFFTAccDcmp[k][l], pDcmp[l])
				}
			}

			e.ExternalProdFFTGLWETo(e.buf.ctFFTAcc, e.EvalKey.BlindRotateKey.Value[j], e.buf.ctFFTAccDcmp)
			for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
				e.PolyEvaluator.InvFFTToUnsafe(ctOut.Value[k], e.buf.ctFFTAcc.Value[k])
			}
		}
	}

	e.PermuteGLWETo(e.buf.ctPermute, ctOut, -5)
	e.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKey[skipCnt])

	for i := e.Params.baseParams.PolyRank()/2 - 1; i > 0; i-- {
		if _, ok := ctAutIdxMap[i]; ok {
			if skipCnt != 0 {
				e.PermuteGLWETo(e.buf.ctPermute, ctOut, num.ModExp(5, skipCnt, 2*e.Params.baseParams.PolyRank()))
				e.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKey[skipCnt])
				skipCnt = 0
			}

			for _, j := range ctAutIdxMap[i] {
				for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
					e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[k], e.Params.baseParams.BlindRotateParams())
					for l := 0; l < e.Params.baseParams.BlindRotateParams().Level(); l++ {
						e.PolyEvaluator.FFTTo(e.buf.ctFFTAccDcmp[k][l], pDcmp[l])
					}
				}

				e.ExternalProdFFTGLWETo(e.buf.ctFFTAcc, e.EvalKey.BlindRotateKey.Value[j], e.buf.ctFFTAccDcmp)
				for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
					e.PolyEvaluator.InvFFTToUnsafe(ctOut.Value[k], e.buf.ctFFTAcc.Value[k])
				}
			}
		}
		skipCnt++

		if skipCnt == e.Params.windowSize || i == 1 {
			e.PermuteGLWETo(e.buf.ctPermute, ctOut, num.ModExp(5, skipCnt, 2*e.Params.baseParams.PolyRank()))
			e.KeySwitchGLWETo(ctOut, e.buf.ctPermute, e.EvalKey.GaloisKey[skipCnt])
			skipCnt = 0
		}
	}

	if _, ok := ctAutIdxMap[0]; ok {
		for _, j := range ctAutIdxMap[0] {
			for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[k], e.Params.baseParams.BlindRotateParams())
				for l := 0; l < e.Params.baseParams.BlindRotateParams().Level(); l++ {
					e.PolyEvaluator.FFTTo(e.buf.ctFFTAccDcmp[k][l], pDcmp[l])
				}
			}

			e.ExternalProdFFTGLWETo(e.buf.ctFFTAcc, e.EvalKey.BlindRotateKey.Value[j], e.buf.ctFFTAccDcmp)
			for k := 0; k < e.Params.baseParams.GLWERank()+1; k++ {
				e.PolyEvaluator.InvFFTToUnsafe(ctOut.Value[k], e.buf.ctFFTAcc.Value[k])
			}
		}
	}
}
