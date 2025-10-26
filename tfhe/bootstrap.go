package tfhe

import (
	"math"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.GenLUTTo(e.buf.lut, f)
	return e.BootstrapLUT(ct, e.buf.lut)
}

// BootstrapFuncTo bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *Evaluator[T]) BootstrapFuncTo(ctOut, ct LWECiphertext[T], f func(int) int) {
	e.GenLUTTo(e.buf.lut, f)
	e.BootstrapLUTTo(ctOut, ct, e.buf.lut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *Evaluator[T]) BootstrapLUT(ct LWECiphertext[T], lut LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.BootstrapLUTTo(ctOut, ct, lut)
	return ctOut
}

// BootstrapLUTTo bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *Evaluator[T]) BootstrapLUTTo(ctOut, ct LWECiphertext[T], lut LookUpTable[T]) {
	switch e.Params.bootstrapOrder {
	case OrderKeySwitchBlindRotate:
		e.DefaultKeySwitchTo(e.buf.ctKeySwitch, ct)
		e.BlindRotateTo(e.buf.ctRotate, e.buf.ctKeySwitch, lut)
		e.buf.ctRotate.AsLWECiphertextTo(0, ctOut)
	case OrderBlindRotateKeySwitch:
		e.BlindRotateTo(e.buf.ctRotate, ct, lut)
		e.buf.ctRotate.AsLWECiphertextTo(0, e.buf.ctExtract)
		e.DefaultKeySwitchTo(ctOut, e.buf.ctExtract)
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LUTSize.
func (e *Evaluator[T]) ModSwitch(x T) int {
	return int(math.Round(e.modSwitchConst*float64(x))) % (2 * e.Params.lutSize)
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.BlindRotateTo(ctOut, ct, lut)
	return ctOut
}

// BlindRotateTo computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *Evaluator[T]) BlindRotateTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut LookUpTable[T]) {
	switch {
	case e.Params.lutSize > e.Params.polyRank:
		e.blindRotateExtendedTo(ctOut, ct, lut)
	case e.Params.blockSize > 1:
		e.blindRotateBlockTo(ctOut, ct, lut)
	default:
		e.blindRotateOriginalTo(ctOut, ct, lut)
	}
}

// blindRotateExtendedTo computes the blind rotation when LUTSize > PolyRank.
// This is equivalent to the blind rotation algorithm using extended polynomials, as explained in https://eprint.iacr.org/2023/402.
func (e *Evaluator[T]) blindRotateExtendedTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut LookUpTable[T]) {
	pDcmp := e.Decomposer.buf.pDcmp[:e.Params.blindRotateParams.level]

	b2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[0])
	b2NMono, b2NIdx := b2N/e.Params.lutExtendFactor, b2N%e.Params.lutExtendFactor

	for i, ii := 0, e.Params.lutExtendFactor-b2NIdx; i < b2NIdx; i, ii = i+1, ii+1 {
		e.PolyEvaluator.MonomialMulPolyTo(e.buf.ctAcc[ii].Value[0], lut.Value[i], b2NMono+1)
	}
	for i, ii := b2NIdx, 0; i < e.Params.lutExtendFactor; i, ii = i+1, ii+1 {
		e.PolyEvaluator.MonomialMulPolyTo(e.buf.ctAcc[ii].Value[0], lut.Value[i], b2NMono)
	}

	for i := 0; i < e.Params.lutExtendFactor; i++ {
		for j := 1; j < e.Params.glweRank+1; j++ {
			e.buf.ctAcc[i].Value[j].Clear()
		}
	}

	for j := 0; j < e.Params.lutExtendFactor; j++ {
		e.Decomposer.DecomposePolyTo(pDcmp, e.buf.ctAcc[j].Value[0], e.Params.blindRotateParams)
		for l := 0; l < e.Params.blindRotateParams.level; l++ {
			e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[j][0][l], pDcmp[l])
		}
	}

	a2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[1])
	a2NMono, a2NIdx := a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

	for k := 0; k < e.Params.lutExtendFactor; k++ {
		e.GadgetProdFFTGLWETo(e.buf.fctBlockAcc[k], e.EvalKey.BlindRotateKey.Value[0].Value[0], e.buf.fctAccDcmp[k][0])
	}

	if a2NIdx == 0 {
		e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
		for k := 0; k < e.Params.lutExtendFactor; k++ {
			e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[k], e.buf.fMono)
		}
	} else {
		e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
		for k, kk := 0, e.Params.lutExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
			e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
			e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
		}
		e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono)
		for k, kk := a2NIdx, 0; k < e.Params.lutExtendFactor; k, kk = k+1, kk+1 {
			e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
			e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
		}
	}

	for j := 1; j < e.Params.blockSize; j++ {
		a2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[j+1])
		a2NMono, a2NIdx := a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

		for k := 0; k < e.Params.lutExtendFactor; k++ {
			e.GadgetProdFFTGLWETo(e.buf.fctBlockAcc[k], e.EvalKey.BlindRotateKey.Value[j].Value[0], e.buf.fctAccDcmp[k][0])
		}

		if a2NIdx == 0 {
			e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
			for k := 0; k < e.Params.lutExtendFactor; k++ {
				e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[k], e.buf.fMono)
			}
		} else {
			e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
			for k, kk := 0, e.Params.lutExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
				e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
			}
			e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono)
			for k, kk := a2NIdx, 0; k < e.Params.lutExtendFactor; k, kk = k+1, kk+1 {
				e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
				e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
			}
		}
	}

	for j := 0; j < e.Params.lutExtendFactor; j++ {
		for k := 0; k < e.Params.glweRank+1; k++ {
			e.PolyEvaluator.InvFFTAddToUnsafe(e.buf.ctAcc[j].Value[k], e.buf.fctAcc[j].Value[k])
		}
	}

	for i := 1; i < e.Params.blockCount-1; i++ {
		for j := 0; j < e.Params.lutExtendFactor; j++ {
			for k := 0; k < e.Params.glweRank+1; k++ {
				e.Decomposer.DecomposePolyTo(pDcmp, e.buf.ctAcc[j].Value[k], e.Params.blindRotateParams)
				for l := 0; l < e.Params.blindRotateParams.level; l++ {
					e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[j][k][l], pDcmp[l])
				}
			}
		}

		a2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[i*e.Params.blockSize+1])
		a2NMono, a2NIdx := a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

		for k := 0; k < e.Params.lutExtendFactor; k++ {
			e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[k], e.EvalKey.BlindRotateKey.Value[i*e.Params.blockSize], e.buf.fctAccDcmp[k])
		}

		if a2NIdx == 0 {
			e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
			for k := 0; k < e.Params.lutExtendFactor; k++ {
				e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[k], e.buf.fMono)
			}
		} else {
			e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
			for k, kk := 0, e.Params.lutExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
				e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
			}
			e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono)
			for k, kk := a2NIdx, 0; k < e.Params.lutExtendFactor; k, kk = k+1, kk+1 {
				e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
				e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
			}
		}

		for j := i*e.Params.blockSize + 1; j < (i+1)*e.Params.blockSize; j++ {
			a2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[j+1])
			a2NMono, a2NIdx := a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

			for k := 0; k < e.Params.lutExtendFactor; k++ {
				e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[k], e.EvalKey.BlindRotateKey.Value[j], e.buf.fctAccDcmp[k])
			}

			if a2NIdx == 0 {
				e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
				for k := 0; k < e.Params.lutExtendFactor; k++ {
					e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[k], e.buf.fMono)
				}
			} else {
				e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
				for k, kk := 0, e.Params.lutExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
					e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
					e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
				}
				e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono)
				for k, kk := a2NIdx, 0; k < e.Params.lutExtendFactor; k, kk = k+1, kk+1 {
					e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[k], e.buf.fctBlockAcc[kk], e.buf.fMono)
					e.SubFFTGLWETo(e.buf.fctAcc[k], e.buf.fctAcc[k], e.buf.fctBlockAcc[k])
				}
			}
		}

		for j := 0; j < e.Params.lutExtendFactor; j++ {
			for k := 0; k < e.Params.glweRank+1; k++ {
				e.PolyEvaluator.InvFFTAddToUnsafe(e.buf.ctAcc[j].Value[k], e.buf.fctAcc[j].Value[k])
			}
		}
	}

	for j := 0; j < e.Params.lutExtendFactor; j++ {
		for k := 0; k < e.Params.glweRank+1; k++ {
			e.Decomposer.DecomposePolyTo(pDcmp, e.buf.ctAcc[j].Value[k], e.Params.blindRotateParams)
			for l := 0; l < e.Params.blindRotateParams.level; l++ {
				e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[j][k][l], pDcmp[l])
			}
		}
	}

	a2N = 2*e.Params.lutSize - e.ModSwitch(ct.Value[e.Params.lweDimension-e.Params.blockSize+1])
	a2NMono, a2NIdx = a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

	if a2NIdx == 0 {
		e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[e.Params.lweDimension-e.Params.blockSize], e.buf.fctAccDcmp[0])
		e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
		e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
	} else {
		kk := e.Params.lutExtendFactor - a2NIdx
		e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[e.Params.lweDimension-e.Params.blockSize], e.buf.fctAccDcmp[0])
		e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[kk], e.EvalKey.BlindRotateKey.Value[e.Params.lweDimension-e.Params.blockSize], e.buf.fctAccDcmp[kk])
		e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
		e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[kk], e.buf.fMono)
		e.SubFFTGLWETo(e.buf.fctAcc[0], e.buf.fctAcc[0], e.buf.fctBlockAcc[0])
	}

	for j := e.Params.lweDimension - e.Params.blockSize + 1; j < e.Params.lweDimension; j++ {
		a2N := 2*e.Params.lutSize - e.ModSwitch(ct.Value[j+1])
		a2NMono, a2NIdx := a2N/e.Params.lutExtendFactor, a2N%e.Params.lutExtendFactor

		if a2NIdx == 0 {
			e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[j], e.buf.fctAccDcmp[0])
			e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, a2NMono)
			e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
		} else {
			kk := e.Params.lutExtendFactor - a2NIdx
			e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[j], e.buf.fctAccDcmp[0])
			e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[kk], e.EvalKey.BlindRotateKey.Value[j], e.buf.fctAccDcmp[kk])
			e.PolyEvaluator.MonomialFFTTo(e.buf.fMono, a2NMono+1)
			e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[kk], e.buf.fMono)
			e.SubFFTGLWETo(e.buf.fctAcc[0], e.buf.fctAcc[0], e.buf.fctBlockAcc[0])
		}
	}

	for k := 0; k < e.Params.glweRank+1; k++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(e.buf.ctAcc[0].Value[k], e.buf.fctAcc[0].Value[k])
		ctOut.Value[k].CopyFrom(e.buf.ctAcc[0].Value[k])
	}
}

// blindRotateBlockTo computes the blind rotation when PolyRank = LUTSize and BlockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *Evaluator[T]) blindRotateBlockTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut LookUpTable[T]) {
	pDcmp := e.Decomposer.buf.pDcmp[:e.Params.blindRotateParams.level]

	e.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Params.glweRank+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[0], e.Params.blindRotateParams)
	for k := 0; k < e.Params.blindRotateParams.level; k++ {
		e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[0][0][k], pDcmp[k])
	}

	e.GadgetProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[0].Value[0], e.buf.fctAccDcmp[0][0])
	e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[1]))
	e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
	for j := 1; j < e.Params.blockSize; j++ {
		e.GadgetProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[j].Value[0], e.buf.fctAccDcmp[0][0])
		e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[j+1]))
		e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
	}

	for j := 0; j < e.Params.glweRank+1; j++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.fctAcc[0].Value[j])
	}

	for i := 1; i < e.Params.blockCount; i++ {
		for j := 0; j < e.Params.glweRank+1; j++ {
			e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[j], e.Params.blindRotateParams)
			for k := 0; k < e.Params.blindRotateParams.level; k++ {
				e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[0][j][k], pDcmp[k])
			}
		}

		e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[i*e.Params.blockSize], e.buf.fctAccDcmp[0])
		e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[i*e.Params.blockSize+1]))
		e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
		for j := i*e.Params.blockSize + 1; j < (i+1)*e.Params.blockSize; j++ {
			e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[j], e.buf.fctAccDcmp[0])
			e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[j+1]))
			e.FFTPolyMulAddFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
		}

		for j := 0; j < e.Params.glweRank+1; j++ {
			e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.fctAcc[0].Value[j])
		}
	}
}

// blindRotateOriginalTo computes the blind rotation when PolyRank = LUTSize and BlockSize = 1.
// This is equivalent to the original blind rotation algorithm.
func (e *Evaluator[T]) blindRotateOriginalTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut LookUpTable[T]) {
	pDcmp := e.Decomposer.buf.pDcmp[:e.Params.blindRotateParams.level]

	e.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Params.glweRank+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[0], e.Params.blindRotateParams)
	for k := 0; k < e.Params.blindRotateParams.level; k++ {
		e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[0][0][k], pDcmp[k])
	}

	e.GadgetProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[0].Value[0], e.buf.fctAccDcmp[0][0])
	e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[1]))
	e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)
	for j := 0; j < e.Params.glweRank+1; j++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.fctAcc[0].Value[j])
	}

	for i := 1; i < e.Params.lweDimension; i++ {
		for j := 0; j < e.Params.glweRank+1; j++ {
			e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[j], e.Params.blindRotateParams)
			for k := 0; k < e.Params.blindRotateParams.level; k++ {
				e.PolyEvaluator.FFTTo(e.buf.fctAccDcmp[0][j][k], pDcmp[k])
			}
		}

		e.ExternalProdFFTGLWETo(e.buf.fctBlockAcc[0], e.EvalKey.BlindRotateKey.Value[i], e.buf.fctAccDcmp[0])
		e.PolyEvaluator.MonomialSubOneFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[i+1]))
		e.FFTPolyMulFFTGLWETo(e.buf.fctAcc[0], e.buf.fctBlockAcc[0], e.buf.fMono)

		for j := 0; j < e.Params.glweRank+1; j++ {
			e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.fctAcc[0].Value[j])
		}
	}
}

// DefaultKeySwitch performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext will be of length LWEDimension + 1.
func (e *Evaluator[T]) DefaultKeySwitch(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Params.lweDimension)
	e.DefaultKeySwitchTo(ctOut, ct)
	return ctOut
}

// DefaultKeySwitchTo performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext should be of length LWEDimension + 1.
func (e *Evaluator[T]) DefaultKeySwitchTo(ctOut, ct LWECiphertext[T]) {
	cDcmp := e.Decomposer.buf.cDcmp[:e.Params.keySwitchParams.level]

	copy(ctOut.Value, ct.Value[:e.Params.lweDimension+1])
	for i, ii := e.Params.lweDimension, 0; i < e.Params.glweDimension; i, ii = i+1, ii+1 {
		e.Decomposer.DecomposeScalarTo(cDcmp, ct.Value[i+1], e.Params.keySwitchParams)
		for j := 0; j < e.Params.keySwitchParams.level; j++ {
			e.ScalarMulAddLWETo(ctOut, e.EvalKey.KeySwitchKey.Value[ii].Value[j], cDcmp[j])
		}
	}
}
