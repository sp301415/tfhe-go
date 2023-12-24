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
type LookUpTable[T Tint] poly.Poly[T]

// NewLookUpTable allocates an empty lookup table.
func NewLookUpTable[T Tint](params Parameters[T]) LookUpTable[T] {
	return LookUpTable[T](poly.New[T](params.polyLargeDegree))
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	return LookUpTable[T](poly.Poly[T](lut).Copy())
}

// CopyFrom copies values from a LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	vec.CopyAssign(lutIn.Coeffs, lut.Coeffs)
}

// Clear clears the LUT.
func (lut *LookUpTable[T]) Clear() {
	vec.Fill(lut.Coeffs, 0)
}

// GenLookUpTable generates a lookup table based on function f and returns it.
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

// GenLookUpTableFull generates a lookup table based on function f and returns it.
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
	if e.Parameters.bootstrapOrder == OrderKeySwitchBlindRotate {
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitch)
		e.BlindRotateAssign(e.buffer.ctKeySwitch, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, ctOut)
	} else {
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// ModSwitch calculates round(2N * x / Q) mod 2N.
func (e *Evaluator[T]) ModSwitch(x T) int {
	x2N := int(num.RoundRatioBits(x, e.Parameters.sizeT-(e.Parameters.polyLargeDegreeLog+1))) & (2*e.Parameters.polyLargeDegree - 1)
	if x2N >= e.Parameters.polyLargeDegree {
		x2N -= 2 * e.Parameters.polyLargeDegree
	}
	return x2N
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	if e.Parameters.polyLargeDegree > e.Parameters.polyDegree {
		e.blindRotateExtendedAssign(ct, lut, ctOut)
	} else {
		if e.Parameters.blockSize == 1 {
			e.blindRotateOriginalAssign(ct, lut, ctOut)
		} else {
			e.blindRotateBlockAssign(ct, lut, ctOut)
		}
	}
}

// blindRotateExtendedAssign calculates the blind rotation when polyLargeDegree > polyDegree.
// This is equivalent to the blind rotation algorithm using extended polynomials, as explained in https://eprint.iacr.org/2023/402.
func (e *Evaluator[T]) blindRotateExtendedAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctAccFourierDecomposedSub := e.buffer.ctAccFourierDecomposed[e.Parameters.polyExtendFactor]

	// Implementation of Algorithm 4 from https://eprint.iacr.org/2023/402
	b2N := -e.ModSwitch(ct.Value[0])
	if b2N < 0 {
		b2N += 2 * e.Parameters.polyLargeDegree
	}
	b2NSmall, b2NIdx := b2N/e.Parameters.polyExtendFactor, b2N&(e.Parameters.polyExtendFactor-1)

	for i := 0; i < e.Parameters.polyExtendFactor; i++ {
		ii := (i + b2N) & (e.Parameters.polyExtendFactor - 1)
		for j := 0; j < e.Parameters.polyDegree; j++ {
			e.buffer.ctAcc[ii].Value[0].Coeffs[j] = lut.Coeffs[j*e.Parameters.polyExtendFactor+i]
		}
		for j := 1; j < e.Parameters.glweDimension+1; j++ {
			e.buffer.ctAcc[ii].Value[j].Clear()
		}
	}

	for i := 0; i < b2NIdx; i++ {
		e.PolyEvaluator.MonomialMulInPlace(e.buffer.ctAcc[i].Value[0], b2NSmall+1)
	}
	for i := b2NIdx; i < e.Parameters.polyExtendFactor; i++ {
		e.PolyEvaluator.MonomialMulInPlace(e.buffer.ctAcc[i].Value[0], b2NSmall)
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		e.FourierDecomposePolyAssign(e.buffer.ctAcc[j].Value[0], e.Parameters.bootstrapParameters, e.buffer.ctAccFourierDecomposed[j][0])
	}

	for j := 0; j < e.Parameters.blockSize; j++ {
		a2N := -e.ModSwitch(ct.Value[j+1])
		if a2N < 0 {
			a2N += 2 * e.Parameters.polyLargeDegree
		}
		a2NSmall, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N&(e.Parameters.polyExtendFactor-1)

		if a2NIdx == 0 {
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			for k := 0; k < e.Parameters.polyExtendFactor; k++ {
				for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
					e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[k][0][m], ctAccFourierDecomposedSub[0][m])
					e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[0][m], e.buffer.ctAccFourierDecomposed[k][0][m], ctAccFourierDecomposedSub[0][m])
				}
				e.GadgetProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], ctAccFourierDecomposedSub[0], e.buffer.ctAcc[k])
			}
		} else {
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
			for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
				for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
					e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[kk][0][m], ctAccFourierDecomposedSub[0][m])
					e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[0][m], e.buffer.ctAccFourierDecomposed[k][0][m], ctAccFourierDecomposedSub[0][m])
				}
				e.GadgetProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], ctAccFourierDecomposedSub[0], e.buffer.ctAcc[k])
			}

			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
				for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
					e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[kk][0][m], ctAccFourierDecomposedSub[0][m])
					e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[0][m], e.buffer.ctAccFourierDecomposed[k][0][m], ctAccFourierDecomposedSub[0][m])
				}
				e.GadgetProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], ctAccFourierDecomposedSub[0], e.buffer.ctAcc[k])
			}
		}
	}

	for i := 1; i < e.Parameters.blockCount-1; i++ {
		for j := 0; j < e.Parameters.polyExtendFactor; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierDecomposePolyAssign(e.buffer.ctAcc[j].Value[k], e.Parameters.bootstrapParameters, e.buffer.ctAccFourierDecomposed[j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			a2N := -e.ModSwitch(ct.Value[j+1])
			if a2N < 0 {
				a2N += 2 * e.Parameters.polyLargeDegree
			}
			a2NSmall, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N&(e.Parameters.polyExtendFactor-1)

			if a2NIdx == 0 {
				e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
				for k := 0; k < e.Parameters.polyExtendFactor; k++ {
					for l := 0; l < e.Parameters.glweDimension+1; l++ {
						for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
							e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[k][l][m], ctAccFourierDecomposedSub[l][m])
							e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[l][m], e.buffer.ctAccFourierDecomposed[k][l][m], ctAccFourierDecomposedSub[l][m])
						}
					}
					e.ExternalProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j], ctAccFourierDecomposedSub, e.buffer.ctAcc[k])
				}
			} else {
				e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
				for k, kk := 0, e.Parameters.polyExtendFactor-a2NIdx; k < a2NIdx; k, kk = k+1, kk+1 {
					for l := 0; l < e.Parameters.glweDimension+1; l++ {
						for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
							e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[kk][l][m], ctAccFourierDecomposedSub[l][m])
							e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[l][m], e.buffer.ctAccFourierDecomposed[k][l][m], ctAccFourierDecomposedSub[l][m])
						}
					}
					e.ExternalProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j], ctAccFourierDecomposedSub, e.buffer.ctAcc[k])
				}

				e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
				for k, kk := a2NIdx, 0; k < e.Parameters.polyExtendFactor; k, kk = k+1, kk+1 {
					for l := 0; l < e.Parameters.glweDimension+1; l++ {
						for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
							e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[kk][l][m], ctAccFourierDecomposedSub[l][m])
							e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[l][m], e.buffer.ctAccFourierDecomposed[k][l][m], ctAccFourierDecomposedSub[l][m])
						}
					}
					e.ExternalProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j], ctAccFourierDecomposedSub, e.buffer.ctAcc[k])
				}
			}
		}
	}

	for j := 0; j < e.Parameters.polyExtendFactor; j++ {
		for k := 0; k < e.Parameters.glweDimension+1; k++ {
			e.FourierDecomposePolyAssign(e.buffer.ctAcc[j].Value[k], e.Parameters.bootstrapParameters, e.buffer.ctAccFourierDecomposed[j][k])
		}
	}

	for j := e.Parameters.lweDimension - e.Parameters.blockSize; j < e.Parameters.lweDimension; j++ {
		a2N := -e.ModSwitch(ct.Value[j+1])
		if a2N < 0 {
			a2N += 2 * e.Parameters.polyLargeDegree
		}
		a2NSmall, a2NIdx := a2N/e.Parameters.polyExtendFactor, a2N&(e.Parameters.polyExtendFactor-1)

		if a2NIdx == 0 {
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall, e.buffer.fMono)
			for l := 0; l < e.Parameters.glweDimension+1; l++ {
				for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
					e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[0][l][m], ctAccFourierDecomposedSub[l][m])
					e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[l][m], e.buffer.ctAccFourierDecomposed[0][l][m], ctAccFourierDecomposedSub[l][m])
				}
			}
			e.ExternalProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j], ctAccFourierDecomposedSub, e.buffer.ctAcc[0])
		} else {
			e.FourierEvaluator.MonomialToFourierPolyAssign(a2NSmall+1, e.buffer.fMono)
			kk := e.Parameters.polyExtendFactor - a2NIdx
			for l := 0; l < e.Parameters.glweDimension+1; l++ {
				for m := 0; m < e.Parameters.bootstrapParameters.level; m++ {
					e.FourierEvaluator.MulAssign(e.buffer.fMono, e.buffer.ctAccFourierDecomposed[kk][l][m], ctAccFourierDecomposedSub[l][m])
					e.FourierEvaluator.SubAssign(ctAccFourierDecomposedSub[l][m], e.buffer.ctAccFourierDecomposed[0][l][m], ctAccFourierDecomposedSub[l][m])
				}
			}
			e.ExternalProductFourierDecomposedAddAssign(e.EvaluationKey.BootstrapKey.Value[j], ctAccFourierDecomposedSub, e.buffer.ctAcc[0])
		}
	}

	ctOut.CopyFrom(e.buffer.ctAcc[0])
}

// blindRotateBlockAssign calculates the blind rotation when blockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *Evaluator[T]) blindRotateBlockAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()

	polyDecomposed := e.buffer.polyDecomposed[:e.Parameters.bootstrapParameters.level]

	// Implementation of Algorithm 2 and Section 5.1 from https://eprint.iacr.org/2023/958
	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), -e.ModSwitch(ct.Value[0]), ctOut.Value[0])

	e.DecomposePolyAssign(ctOut.Value[0], e.Parameters.bootstrapParameters, polyDecomposed)
	for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][0][k])
	}

	for j := 0; j < e.Parameters.blockSize; j++ {
		e.GadgetProductFourierDecomposedAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[0][0], e.buffer.ctAcc[0])
		e.MonomialSubOneMulAddAssign(e.buffer.ctAcc[0], -e.ModSwitch(ct.Value[j+1]), ctOut)
	}

	for i := 1; i < e.Parameters.blockCount; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.DecomposePolyAssign(ctOut.Value[j], e.Parameters.bootstrapParameters, polyDecomposed)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductFourierDecomposedAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctAcc[0])
			e.MonomialSubOneMulAddAssign(e.buffer.ctAcc[0], -e.ModSwitch(ct.Value[j+1]), ctOut)
		}
	}
}

// blindRotateOriginalAssign calculates the blind rotation when blockSize == 1.
// This is equivalent to the original blind rotation algorithm.
func (e *Evaluator[T]) blindRotateOriginalAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()

	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), -e.ModSwitch(ct.Value[0]), ctOut.Value[0])

	e.PolyEvaluator.MonomialSubOneMulAssign(ctOut.Value[0], -e.ModSwitch(ct.Value[1]), e.buffer.ctAcc[0].Value[0])
	e.GadgetProductAddAssign(e.EvaluationKey.BootstrapKey.Value[0].Value[0], e.buffer.ctAcc[0].Value[0], ctOut)
	for i := 1; i < e.Parameters.lweDimension; i++ {
		e.MonomialSubOneMulAssign(ctOut, -e.ModSwitch(ct.Value[i+1]), e.buffer.ctAcc[0])
		e.ExternalProductAddAssign(e.EvaluationKey.BootstrapKey.Value[i], e.buffer.ctAcc[0], ctOut)
	}
}

// SampleExtract extracts LWE ciphertext of given index from GLWE ciphertext and returns it.
func (e *Evaluator[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweLargeDimension)
	e.SampleExtractAssign(ct, index, ctOut)
	return ctOut
}

// SampleExtractAssign extracts LWE ciphertext of given index from GLWE ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) SampleExtractAssign(ct GLWECiphertext[T], index int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[index]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < e.Parameters.glweDimension; i++ {
		start := i * e.Parameters.polyDegree
		end := (i + 1) * e.Parameters.polyDegree

		vec.ReverseAssign(ctMask[i].Coeffs, ctOutMask[start:end])

		vec.RotateInPlace(ctOutMask[start:end], index+1)
		vec.NegAssign(ctOutMask[start+index+1:end], ctOutMask[start+index+1:end])
	}
}

// KeySwitch switches key of ct, and returns a new ciphertext.
// Input ciphertext should be of dimension ksk.InputLWEDimension + 1,
// and output ciphertext will be of dimension ksk.OutputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](ksk.OutputLWEDimension())
	e.KeySwitchAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchAssign switches key of ct, and writes it to ctOut.
// Input ciphertext should be of dimension ksk.InputLWEDimension + 1,
// and output ciphertext should be of dimension ksk.OutputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchAssign(ct LWECiphertext[T], ksk KeySwitchKey[T], ctOut LWECiphertext[T]) {
	decomposed := e.getDecomposedBuffer(ksk.GadgetParameters)

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

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext will be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweDimension)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext should be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	vec.CopyAssign(ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)

	decomposed := e.buffer.decomposed[:e.Parameters.keyswitchParameters.level]

	for i, ii := e.Parameters.lweDimension, 0; i < e.Parameters.lweLargeDimension; i, ii = i+1, ii+1 {
		e.DecomposeAssign(ct.Value[i+1], e.Parameters.keyswitchParameters, decomposed)
		for j := 0; j < e.Parameters.keyswitchParameters.level; j++ {
			e.ScalarMulAddLWEAssign(e.EvaluationKey.KeySwitchKey.Value[ii].Value[j], decomposed[j], ctOut)
		}
	}
}
