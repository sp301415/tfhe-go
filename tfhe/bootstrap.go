package tfhe

import (
	"math"

	"github.com/sp301415/tfhe-go/math/vec"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *Evaluator[T]) BootstrapFuncAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *Evaluator[T]) BootstrapLUT(ct LWECiphertext[T], lut LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *Evaluator[T]) BootstrapLUTAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut LWECiphertext[T]) {
	switch e.Parameters.bootstrapOrder {
	case OrderKeySwitchBlindRotate:
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitchForBootstrap)
		e.BlindRotateAssign(e.buffer.ctKeySwitchForBootstrap, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	case OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LookUpTableSize.
func (e *Evaluator[T]) ModSwitch(x T) int {
	return int(math.Round(e.modSwitchConstant*float64(x))) % (2 * e.Parameters.lookUpTableSize)
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	switch {
	case e.Parameters.lookUpTableSize > e.Parameters.polyDegree:
		e.blindRotateExtendedAssign(ct, lut, ctOut)
	case e.Parameters.blockSize > 1:
		e.blindRotateBlockAssign(ct, lut, ctOut)
	default:
		e.blindRotateOriginalAssign(ct, lut, ctOut)
	}
}

// blindRotateExtendedAssign computes the blind rotation when LookUpTableSize > PolyDegree.
// This is equivalent to the blind rotation algorithm using extended polynomials, as explained in https://eprint.iacr.org/2023/402.
func (e *Evaluator[T]) blindRotateExtendedAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.buffer.polyDecomposed[:e.Parameters.blindRotateParameters.level]

	b2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[0])
	b2NMono, b2NIdx := b2N/e.Parameters.polyExtendFactor, b2N%e.Parameters.polyExtendFactor

	for i, ii := 0, e.Parameters.polyExtendFactor-b2NIdx; i < b2NIdx; i, ii = i+1, ii+1 {
		e.PolyEvaluator.MonomialMulPolyAssign(lut.Value[i], b2NMono+1, e.buffer.ctAcc[ii].Value[0])
	}
	for i, ii := b2NIdx, 0; i < e.Parameters.polyExtendFactor; i, ii = i+1, ii+1 {
		e.PolyEvaluator.MonomialMulPolyAssign(lut.Value[i], b2NMono, e.buffer.ctAcc[ii].Value[0])
	}

	for i := 0; i < e.Parameters.polyExtendFactor; i++ {
		for j := 1; j < e.Parameters.glweRank+1; j++ {
			e.buffer.ctAcc[i].Value[j].Clear()
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		e.Decomposer.DecomposePolyAssign(e.buffer.ctAcc[j].Value[0], e.Parameters.blindRotateParameters, polyDecomposed)
		for l := 0; l < e.Parameters.blindRotateParameters.level; l++ {
			e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][0][l])
		}
	}

	a2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[1])
	a2NMono, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

	for k := 0; k < e.Parameters.polyExtendFactor; k++ {
		e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[k][0], e.buffer.ctBlockFourierAcc[k])
	}

	if a2NIdx == 0 {
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
		for k := 0; k < e.Parameters.polyExtendFactor; k++ {
			e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
		}
	} else {
		e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
		for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
			e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
			e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
		}
		e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono, e.buffer.fMono)
		for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
			e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
			e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
		}
	}

	for j := 1; j < e.Parameters.blockSize; j++ {
		a2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[j+1])
		a2NMono, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

		for k := 0; k < e.Parameters.polyExtendFactor; k++ {
			e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[k][0], e.buffer.ctBlockFourierAcc[k])
		}

		if a2NIdx == 0 {
			e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
			}
		} else {
			e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
			for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
			e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono, e.buffer.fMono)
			for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		for k := 0; k < e.Parameters.glweRank+1; k++ {
			e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[j].Value[k], e.buffer.ctAcc[j].Value[k])
		}
	}

	for i := 1; i < e.Parameters.blockCount-1; i++ {
		for j := 0; j < e.Parameters.polyExtendFactor; j++ {
			for k := 0; k < e.Parameters.glweRank+1; k++ {
				e.Decomposer.DecomposePolyAssign(e.buffer.ctAcc[j].Value[k], e.Parameters.blindRotateParameters, polyDecomposed)
				for l := 0; l < e.Parameters.blindRotateParameters.level; l++ {
					e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][k][l])
				}
			}
		}

		a2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[i*e.Parameters.blockSize+1])
		a2NMono, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

		for k := 0; k < e.Parameters.polyExtendFactor; k++ {
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[i*e.Parameters.blockSize], e.buffer.ctAccFourierDecomposed[k], e.buffer.ctBlockFourierAcc[k])
		}

		if a2NIdx == 0 {
			e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
			}
		} else {
			e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
			for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
			e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono, e.buffer.fMono)
			for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
				e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
		}

		for j := i*e.Parameters.blockSize + 1; j < (i+1)*e.Parameters.blockSize; j++ {
			a2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[j+1])
			a2NMono, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed[k], e.buffer.ctBlockFourierAcc[k])
			}

			if a2NIdx == 0 {
				e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
				for k := 0; k < e.Parameters.polyExtendFactor; k++ {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				}
			} else {
				e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
				for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
					e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
				}
				e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono, e.buffer.fMono)
				for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
					e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
				}
			}
		}

		for j := 0; j < e.Parameters.polyExtendFactor; j++ {
			for k := 0; k < e.Parameters.glweRank+1; k++ {
				e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[j].Value[k], e.buffer.ctAcc[j].Value[k])
			}
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		for k := 0; k < e.Parameters.glweRank+1; k++ {
			e.Decomposer.DecomposePolyAssign(e.buffer.ctAcc[j].Value[k], e.Parameters.blindRotateParameters, polyDecomposed)
			for l := 0; l < e.Parameters.blindRotateParameters.level; l++ {
				e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][k][l])
			}
		}
	}

	a2N = 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[e.Parameters.lweDimension-e.Parameters.blockSize+1])
	a2NMono, a2NIdx = a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

	if a2NIdx == 0 {
		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[e.Parameters.lweDimension-e.Parameters.blockSize], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	} else {
		kk := e.Parameters.polyExtendFactor - a2NIdx
		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[e.Parameters.lweDimension-e.Parameters.blockSize], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[e.Parameters.lweDimension-e.Parameters.blockSize], e.buffer.ctAccFourierDecomposed[kk], e.buffer.ctBlockFourierAcc[kk])
		e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[0], e.buffer.ctBlockFourierAcc[0], e.buffer.ctFourierAcc[0])
	}

	for j := e.Parameters.lweDimension - e.Parameters.blockSize + 1; j < e.Parameters.lweDimension; j++ {
		a2N := 2*e.Parameters.lookUpTableSize - e.ModSwitch(ct.Value[j+1])
		a2NMono, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N%e.Parameters.polyExtendFactor

		if a2NIdx == 0 {
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(a2NMono, e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		} else {
			kk := e.Parameters.polyExtendFactor - a2NIdx
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed[kk], e.buffer.ctBlockFourierAcc[kk])
			e.PolyEvaluator.MonomialToFourierPolyAssign(a2NMono+1, e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[0])
			e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[0], e.buffer.ctBlockFourierAcc[0], e.buffer.ctFourierAcc[0])
		}
	}

	for k := 0; k < e.Parameters.glweRank+1; k++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[0].Value[k], e.buffer.ctAcc[0].Value[k])
		ctOut.Value[k].CopyFrom(e.buffer.ctAcc[0].Value[k])
	}
}

// blindRotateBlockAssign computes the blind rotation when PolyDegree = LookUpTableSize and BlockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *Evaluator[T]) blindRotateBlockAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.buffer.polyDecomposed[:e.Parameters.blindRotateParameters.level]

	e.PolyEvaluator.MonomialMulPolyAssign(lut.Value[0], -e.ModSwitch(ct.Value[0]), ctOut.Value[0])
	for i := 1; i < e.Parameters.glweRank+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyAssign(ctOut.Value[0], e.Parameters.blindRotateParameters, polyDecomposed)
	for k := 0; k < e.Parameters.blindRotateParameters.level; k++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][0][k])
	}

	e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctBlockFourierAcc[0])
	e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[1]), e.buffer.fMono)
	e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	for j := 1; j < e.Parameters.blockSize; j++ {
		e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctBlockFourierAcc[0])
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[j+1]), e.buffer.fMono)
		e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	}

	for j := 0; j < e.Parameters.glweRank+1; j++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[0].Value[j], ctOut.Value[j])
	}

	for i := 1; i < e.Parameters.blockCount; i++ {
		for j := 0; j < e.Parameters.glweRank+1; j++ {
			e.Decomposer.DecomposePolyAssign(ctOut.Value[j], e.Parameters.blindRotateParameters, polyDecomposed)
			for k := 0; k < e.Parameters.blindRotateParameters.level; k++ {
				e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][j][k])
			}
		}

		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[i*e.Parameters.blockSize], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[i*e.Parameters.blockSize+1]), e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		for j := i*e.Parameters.blockSize + 1; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[j+1]), e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		}

		for j := 0; j < e.Parameters.glweRank+1; j++ {
			e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[0].Value[j], ctOut.Value[j])
		}
	}
}

// blindRotateOriginalAssign computes the blind rotation when PolyDegree = LookUpTableSize and BlockSize = 1.
// This is equivalent to the original blind rotation algorithm.
func (e *Evaluator[T]) blindRotateOriginalAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.buffer.polyDecomposed[:e.Parameters.blindRotateParameters.level]

	e.PolyEvaluator.MonomialMulPolyAssign(lut.Value[0], -e.ModSwitch(ct.Value[0]), ctOut.Value[0])
	for i := 1; i < e.Parameters.glweRank+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyAssign(ctOut.Value[0], e.Parameters.blindRotateParameters, polyDecomposed)
	for k := 0; k < e.Parameters.blindRotateParameters.level; k++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][0][k])
	}

	e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctBlockFourierAcc[0])
	e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[1]), e.buffer.fMono)
	e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	for j := 0; j < e.Parameters.glweRank+1; j++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[0].Value[j], ctOut.Value[j])
	}

	for i := 1; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < e.Parameters.glweRank+1; j++ {
			e.Decomposer.DecomposePolyAssign(ctOut.Value[j], e.Parameters.blindRotateParameters, polyDecomposed)
			for k := 0; k < e.Parameters.blindRotateParameters.level; k++ {
				e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][j][k])
			}
		}

		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[i], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[i+1]), e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])

		for j := 0; j < e.Parameters.glweRank+1; j++ {
			e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc[0].Value[j], ctOut.Value[j])
		}
	}
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext will be of length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweDimension)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext should be of length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.buffer.scalarDecomposed[:e.Parameters.keySwitchParameters.level]

	vec.CopyAssign(ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)
	for i, ii := e.Parameters.lweDimension, 0; i < e.Parameters.glweDimension; i, ii = i+1, ii+1 {
		e.Decomposer.DecomposeScalarAssign(ct.Value[i+1], e.Parameters.keySwitchParameters, scalarDecomposed)
		for j := 0; j < e.Parameters.keySwitchParameters.level; j++ {
			e.ScalarMulAddLWEAssign(e.EvaluationKey.KeySwitchKey.Value[ii].Value[j], scalarDecomposed[j], ctOut)
		}
	}
}
