package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// LookUpTable is a trivially encrypted GLWE ciphertext that holds
// the lookup table for function evaluations during programmable bootstrapping.
//
// The degree of a LUT equals to PolyLargeDegree.
type LookUpTable[T TorusInt] poly.Poly[T]

// NewLookUpTable allocates an empty lookup table.
func NewLookUpTable[T TorusInt](params Parameters[T]) LookUpTable[T] {
	return LookUpTable[T](poly.NewPoly[T](params.polyLargeDegree))
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	return LookUpTable[T](poly.Poly[T](lut).Copy())
}

// CopyFrom copies values from the LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	vec.CopyAssign(lutIn.Coeffs, lut.Coeffs)
}

// Clear clears the LUT.
func (lut *LookUpTable[T]) Clear() {
	vec.Fill(lut.Coeffs, 0)
}

// GenLookUpTable generates a lookup table based on function f.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTable(f func(int) int) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableAssign generates a lookup table based on function f and writes it to lutOut.
// Input and output of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTableAssign(f func(int) int, lutOut LookUpTable[T]) {
	boxSize := 1 << (e.Parameters.polyLargeDegreeLog - e.Parameters.messageModulusLog)
	for x := 0; x < 1<<e.Parameters.messageModulusLog; x++ {
		y := e.EncodeLWE(f(x)).Value
		for xx := x * boxSize; xx < (x+1)*boxSize; xx++ {
			lutOut.Coeffs[xx] = y
		}
	}

	vec.RotateInPlace(lutOut.Coeffs, -boxSize/2)
	for i := e.Parameters.polyLargeDegree - boxSize/2; i < e.Parameters.polyLargeDegree; i++ {
		lutOut.Coeffs[i] = -lutOut.Coeffs[i]
	}
}

// GenLookUpTableFull generates a lookup table based on function f.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFull(f func(int) T) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableFullAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableFullAssign generates a lookup table based on function f and writes it to lutOut.
// Output of f is encoded as-is.
func (e *Evaluator[T]) GenLookUpTableFullAssign(f func(int) T, lutOut LookUpTable[T]) {
	boxSize := 1 << (e.Parameters.polyLargeDegreeLog - e.Parameters.messageModulusLog)
	for x := 0; x < 1<<e.Parameters.messageModulusLog; x++ {
		y := f(x)
		for xx := x * boxSize; xx < (x+1)*boxSize; xx++ {
			lutOut.Coeffs[xx] = y
		}
	}

	vec.RotateInPlace(lutOut.Coeffs, -boxSize/2)
	for i := e.Parameters.polyLargeDegree - boxSize/2; i < e.Parameters.polyLargeDegree; i++ {
		lutOut.Coeffs[i] = -lutOut.Coeffs[i]
	}
}

// ClearPaddingBit clears the padding bit of the LWE ciphertext.
func (e *Evaluator[T]) ClearPaddingBit(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ClearPaddingBitAssign(ct, ctOut)
	return ctOut
}

// ClearPaddingBitAssign clears the padding bit of the LWE ciphertext and writes it to ctOut.
func (e *Evaluator[T]) ClearPaddingBitAssign(ct LWECiphertext[T], ctOut LWECiphertext[T]) {
	e.GenLookUpTableFullAssign(func(x int) T { return 1 << (e.Parameters.logQ - 2) }, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, e.buffer.ctPadding)
	e.SubLWEAssign(ct, e.buffer.ctPadding, ctOut)
	ctOut.Value[0] += 1 << (e.Parameters.logQ - 2)
}

// ClearPaddingBitInPlace clears the padding bit of the LWE ciphertext in place.
func (e *Evaluator[T]) ClearPaddingBitInPlace(ct LWECiphertext[T]) {
	e.ClearPaddingBitAssign(ct, ct)
}

// BootstrapFunc returns a bootstrapped LWE ciphertext with resepect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with resepect to given function and writes it to ctOut.
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
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitch)
		e.BlindRotateAssign(e.buffer.ctKeySwitch, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, ctOut)
	case OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// ModSwitch computes x2N = round(2N * x / Q) mod 2N
// and returns x2N as an unsigned representation.
func (e *Evaluator[T]) ModSwitch(x T) int {
	return int(num.RoundRatioBits(x, e.Parameters.logQ-(e.Parameters.polyLargeDegreeLog+1))) & (2*e.Parameters.polyLargeDegree - 1)
}

// ModSwitchNeg computes x2N = round(2N * (-x) / Q) mod 2N
// and returns -x2N as an unsigned representation.
func (e *Evaluator[T]) ModSwitchNeg(x T) int {
	return int(-num.RoundRatioBits(x, e.Parameters.logQ-(e.Parameters.polyLargeDegreeLog+1))) & (2*e.Parameters.polyLargeDegree - 1)
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign computes the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	switch {
	case e.Parameters.polyLargeDegree > e.Parameters.polyDegree:
		e.blindRotateExtendedAssign(ct, lut, ctOut)
	case e.Parameters.blockSize > 1:
		e.blindRotateBlockAssign(ct, lut, ctOut)
	default:
		e.blindRotateOriginalAssign(ct, lut, ctOut)
	}
}

// blindRotateExtendedAssign computes the blind rotation when PolyLargeDegree > PolyDegree.
// This is equivalent to the blind rotation algorithm using extended polynomials, as explained in https://eprint.iacr.org/2023/402.
func (e *Evaluator[T]) blindRotateExtendedAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.buffer.polyDecomposed[:e.Parameters.bootstrapParameters.level]

	b2N := e.ModSwitchNeg(ct.Value[0])
	b2NSmall, b2NIdx := b2N>>e.Parameters.polyExtendFactorLog, b2N&(e.Parameters.polyExtendFactor-1)

	for i := 0; i < e.Parameters.polyExtendFactor; i++ {
		ii := (i + b2N) & (e.Parameters.polyExtendFactor - 1)
		for j := 0; j < e.Parameters.polyDegree; j++ {
			e.buffer.pAcc[ii].Coeffs[j] = lut.Coeffs[j*e.Parameters.polyExtendFactor+i]
		}
	}

	for i := 0; i < b2NIdx; i++ {
		e.PolyEvaluator.MonomialMulInPlace(e.buffer.pAcc[i], b2NSmall+1)
		e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pAcc[i], e.buffer.ctFourierAcc[i].Value[0])
		for j := 1; j < e.Parameters.glweDimension+1; j++ {
			e.buffer.ctFourierAcc[i].Value[j].Clear()
		}
	}
	for i := b2NIdx; i < e.Parameters.polyExtendFactor; i++ {
		e.PolyEvaluator.MonomialMulInPlace(e.buffer.pAcc[i], b2NSmall)
		e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pAcc[i], e.buffer.ctFourierAcc[i].Value[0])
		for j := 1; j < e.Parameters.glweDimension+1; j++ {
			e.buffer.ctFourierAcc[i].Value[j].Clear()
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		e.DecomposePolyAssign(e.buffer.pAcc[j], e.Parameters.bootstrapParameters, polyDecomposed)
		for l := 0; l < e.Parameters.bootstrapParameters.level; l++ {
			e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][0][l])
		}
	}

	for j := 0; j < e.Parameters.blockSize; j++ {
		a2N := e.ModSwitchNeg(ct.Value[j+1])
		a2NSmall, a2NIdx := a2N>>e.Parameters.polyExtendFactorLog, a2N&(e.Parameters.polyExtendFactor-1)

		for k := 0; k < e.Parameters.polyExtendFactor; k++ {
			e.GadgetProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[k][0], e.buffer.ctBlockFourierAcc[k])
		}

		if a2NIdx == 0 {
			e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
			}
		} else {
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
			for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
				e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
			}
		}
	}

	for i := 1; i < e.Parameters.blockCount-1; i++ {
		for j := 0; j < e.Parameters.polyExtendFactor; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierEvaluator.ToPolyAssign(e.buffer.ctFourierAcc[j].Value[k], e.buffer.pAcc[0])
				e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
				for l := 0; l < e.Parameters.bootstrapParameters.level; l++ {
					e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][k][l])
				}
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			a2N := e.ModSwitchNeg(ct.Value[j+1])
			a2NSmall, a2NIdx := a2N>>e.Parameters.polyExtendFactorLog, a2N&(e.Parameters.polyExtendFactor-1)

			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[k], e.buffer.ctBlockFourierAcc[k])
			}

			if a2NIdx == 0 {
				e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(a2NSmall, e.buffer.fMono)
				for k := 0; k < e.Parameters.polyExtendFactor; k++ {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[k], e.buffer.fMono, e.buffer.ctFourierAcc[k])
				}
			} else {
				e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
				for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
					e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
				}
				e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
				for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
					e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[k])
					e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[k], e.buffer.ctBlockFourierAcc[k], e.buffer.ctFourierAcc[k])
				}
			}
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		for k := 0; k < e.Parameters.glweDimension+1; k++ {
			e.FourierEvaluator.ToPolyAssign(e.buffer.ctFourierAcc[j].Value[k], e.buffer.pAcc[0])
			e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
			for l := 0; l < e.Parameters.bootstrapParameters.level; l++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctAccFourierDecomposed[j][k][l])
			}
		}
	}

	for j := e.Parameters.lweDimension - e.Parameters.blockSize; j < e.Parameters.lweDimension; j++ {
		a2N := e.ModSwitchNeg(ct.Value[j+1])
		a2NSmall, a2NIdx := a2N>>e.Parameters.polyExtendFactorLog, a2N&(e.Parameters.polyExtendFactor-1)

		if a2NIdx == 0 {
			e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		} else {
			kk := e.Parameters.polyExtendFactor - a2NIdx
			e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[kk], e.buffer.ctBlockFourierAcc[kk])
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[kk], e.buffer.fMono, e.buffer.ctFourierAcc[0])
			e.SubFourierGLWEAssign(e.buffer.ctFourierAcc[0], e.buffer.ctBlockFourierAcc[0], e.buffer.ctFourierAcc[0])
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc[0].Value[i], ctOut.Value[i])
	}
}

// blindRotateBlockAssign computes the blind rotation when PolyDegree = PolyLargeDegree and BlockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *Evaluator[T]) blindRotateBlockAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.buffer.polyDecomposed[:e.Parameters.bootstrapParameters.level]

	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), e.ModSwitchNeg(ct.Value[0]), e.buffer.pAcc[0])
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pAcc[0], e.buffer.ctFourierAcc[0].Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.buffer.ctFourierAcc[0].Value[i].Clear()
	}

	e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
	for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][0][k])
	}

	for j := 0; j < e.Parameters.blockSize; j++ {
		e.GadgetProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctBlockFourierAcc[0])
		e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(e.ModSwitchNeg(ct.Value[j+1]), e.buffer.fMono)
		e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	}

	for i := 1; i < e.Parameters.blockCount; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.FourierEvaluator.ToPolyAssign(e.buffer.ctFourierAcc[0].Value[j], e.buffer.pAcc[0])
			e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
			e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(e.ModSwitchNeg(ct.Value[j+1]), e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc[0].Value[i], ctOut.Value[i])
	}
}

// blindRotateOriginalAssign computes the blind rotation when PolyDegree = PolyLargeDegree and BlockSize = 1.
// This is equivalent to the original blind rotation algorithm.
func (e *Evaluator[T]) blindRotateOriginalAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.buffer.polyDecomposed[:e.Parameters.bootstrapParameters.level]

	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), e.ModSwitchNeg(ct.Value[0]), e.buffer.pAcc[0])
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pAcc[0], e.buffer.ctFourierAcc[0].Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.buffer.ctFourierAcc[0].Value[i].Clear()
	}

	e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
	for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][0][k])
	}

	e.GadgetProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctBlockFourierAcc[0])
	e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(e.ModSwitchNeg(ct.Value[1]), e.buffer.fMono)
	e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])

	for i := 1; i < e.Parameters.lweDimension; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.FourierEvaluator.ToPolyAssign(e.buffer.ctFourierAcc[0].Value[j], e.buffer.pAcc[0])
			e.DecomposePolyAssign(e.buffer.pAcc[0], e.Parameters.bootstrapParameters, polyDecomposed)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][j][k])
			}
		}

		e.ExternalProductFourierDecomposedFourierAssign(e.EvaluationKey.BootstrapKey.Value[i], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc[0])
		e.FourierEvaluator.MonomialSubOneToFourierPolyAssign(e.ModSwitchNeg(ct.Value[i+1]), e.buffer.fMono)
		e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc[0], e.buffer.fMono, e.buffer.ctFourierAcc[0])
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierAcc[0].Value[i], ctOut.Value[i])
	}
}

// SampleExtract extracts LWE ciphertext of given index from GLWE ciphertext.
// The output ciphertext will be of dimension LWELargeDimension + 1,
// encrypted with LWELargeKey.
func (e *Evaluator[T]) SampleExtract(ct GLWECiphertext[T], idx int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweLargeDimension)
	e.SampleExtractAssign(ct, idx, ctOut)
	return ctOut
}

// SampleExtractAssign extracts LWE ciphertext of given index from GLWE ciphertext and writes it to ctOut.
// The output ciphertext should be of dimension LWELargeDimension + 1,
// and it will be a ciphertext encrypted with LWELargeKey.
func (e *Evaluator[T]) SampleExtractAssign(ct GLWECiphertext[T], idx int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[idx]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < e.Parameters.glweDimension; i++ {
		start := i * e.Parameters.polyDegree
		end := (i + 1) * e.Parameters.polyDegree

		vec.ReverseAssign(ctMask[i].Coeffs, ctOutMask[start:end])

		vec.RotateInPlace(ctOutMask[start:end], idx+1)
		vec.NegAssign(ctOutMask[start+idx+1:end], ctOutMask[start+idx+1:end])
	}
}

// KeySwitch switches key of ct.
// Input ciphertext should be of dimension ksk.InputLWEDimension + 1,
// and output ciphertext will be of dimension ksk.OutputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](ksk.OutputLWEDimension())
	e.KeySwitchAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchAssign switches key of ct and writes it to ctOut.
// Input ciphertext should be of dimension ksk.InputLWEDimension + 1,
// and output ciphertext should be of dimension ksk.OutputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchAssign(ct LWECiphertext[T], ksk KeySwitchKey[T], ctOut LWECiphertext[T]) {
	decomposed := e.DecomposedBuffer(ksk.GadgetParameters)

	e.DecomposeAssign(ct.Value[1], ksk.GadgetParameters, decomposed)
	e.ScalarMulLWEAssign(ksk.Value[0].Value[0], decomposed[0], ctOut)
	for j := 1; j < ksk.GadgetParameters.level; j++ {
		e.ScalarMulAddLWEAssign(ksk.Value[0].Value[j], decomposed[j], ctOut)
	}

	for i := 1; i < ksk.InputLWEDimension(); i++ {
		e.DecomposeAssign(ct.Value[i+1], ksk.GadgetParameters, decomposed)
		for j := 0; j < ksk.GadgetParameters.level; j++ {
			e.ScalarMulAddLWEAssign(ksk.Value[i].Value[j], decomposed[j], ctOut)
		}
	}

	ctOut.Value[0] += ct.Value[0]
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext will be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweDimension)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext should be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	decomposed := e.buffer.decomposed[:e.Parameters.keyswitchParameters.level]

	vec.CopyAssign(ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)
	for i, ii := e.Parameters.lweDimension, 0; i < e.Parameters.lweLargeDimension; i, ii = i+1, ii+1 {
		e.DecomposeAssign(ct.Value[i+1], e.Parameters.keyswitchParameters, decomposed)
		for j := 0; j < e.Parameters.keyswitchParameters.level; j++ {
			e.ScalarMulAddLWEAssign(e.EvaluationKey.KeySwitchKey.Value[ii].Value[j], decomposed[j], ctOut)
		}
	}
}
