package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GenLookUpTable generates a lookup table based on function f.
// Input and output of f is cut by MessageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTable(f []func(int) int) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLookUpTable(e.Parameters)
	e.GenLookUpTableAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableAssign generates a lookup table based on function f and writes it to lutOut.
// Input and output of f is cut by MessageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableAssign(f []func(int) int, lutOut tfhe.LookUpTable[T]) {
	e.GenLookUpTableCustomAssign(f, e.Parameters.MessageModulus(), e.Parameters.Scale(), lutOut)
}

// GenLookUpTableFull generates a lookup table based on function f.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableFull(f []func(int) T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLookUpTable(e.Parameters)
	e.GenLookUpTableFullAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableFullAssign generates a lookup table based on function f and writes it to lutOut.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableFullAssign(f []func(int) T, lutOut tfhe.LookUpTable[T]) {
	e.GenLookUpTableFullCustomAssign(f, e.Parameters.MessageModulus(), lutOut)
}

// GenLookUpTableCustom generates a lookup table based on function f using custom messageModulus and scale.
// Input and output of f is cut by messageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableCustom(f []func(int) int, messageModulus, scale T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLookUpTable(e.Parameters)
	e.GenLookUpTableCustomAssign(f, messageModulus, scale, lutOut)
	return lutOut
}

// GenLookUpTableCustomAssign generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Input and output of f is cut by messageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableCustomAssign(f []func(int) int, messageModulus, scale T, lutOut tfhe.LookUpTable[T]) {
	ff := make([]func(int) T, len(f))
	for i := range f {
		j := i
		ff[i] = func(x int) T { return e.EncodeLWECustom(f[j](x), messageModulus, scale).Value }
	}
	e.GenLookUpTableFullCustomAssign(ff, messageModulus, lutOut)
}

// GenLookUpTableFullCustom generates a lookup table based on function f using custom messageModulus and scale.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableFullCustom(f []func(int) T, messageModulus, scale T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLookUpTable(e.Parameters)
	e.GenLookUpTableFullAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableFullCustomAssign generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLookUpTableFullCustomAssign(f []func(int) T, messageModulus T, lutOut tfhe.LookUpTable[T]) {
	if len(f) > e.LUTCount() {
		panic("Number of functions exceeds LUTCount")
	}

	y := make([]T, e.lutCount)

	for x := 0; x < int(messageModulus); x++ {
		start := num.DivRound(x*e.Parameters.LookUpTableSize(), int(messageModulus))
		end := num.DivRound((x+1)*e.Parameters.LookUpTableSize(), int(messageModulus))
		for i := range f {
			y[i] = f[i](x)
		}
		for xx := start; xx < end; xx += e.lutCount {
			for i := 0; i < e.lutCount; i++ {
				lutOut.Value[xx+i] = y[i]
			}
		}
	}

	offset := num.DivRound(e.Parameters.LookUpTableSize(), int(2*messageModulus))
	vec.RotateInPlace(lutOut.Value, -offset)
	for i := e.Parameters.LookUpTableSize() - offset; i < e.Parameters.LookUpTableSize(); i++ {
		lutOut.Value[i] = -lutOut.Value[i]
	}
}

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapFunc(ct tfhe.LWECiphertext[T], f []func(int) int) []tfhe.LWECiphertext[T] {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
//
// Panics if len(f) > LUTCount.
// If len(ctOut) > LUTCount, only the first LUTCount elements are written.
// Panics if len(ctOut) < LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapFuncAssign(ct tfhe.LWECiphertext[T], f []func(int) int, ctOut []tfhe.LWECiphertext[T]) {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *ManyLUTEvaluator[T]) BootstrapLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) []tfhe.LWECiphertext[T] {
	ctOut := make([]tfhe.LWECiphertext[T], e.lutCount)
	for i := 0; i < e.lutCount; i++ {
		ctOut[i] = tfhe.NewLWECiphertext(e.Parameters)
	}
	e.BootstrapLUTAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
//
// If len(ctOut) > LUTCount, only the first LUTCount elements are written.
// Panics if len(ctOut) < LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapLUTAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut []tfhe.LWECiphertext[T]) {
	switch e.Parameters.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitchForBootstrap)
		e.BlindRotateAssign(e.buffer.ctKeySwitchForBootstrap, lut, e.buffer.ctRotate)
		for i := 0; i < e.lutCount; i++ {
			e.buffer.ctRotate.ToLWECiphertextAssign(i, ctOut[i])
		}
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		for i := 0; i < e.lutCount; i++ {
			e.buffer.ctRotate.ToLWECiphertextAssign(i, e.buffer.ctExtract)
			e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut[i])
		}
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LookUpTableSize.
func (e *ManyLUTEvaluator[T]) ModSwitch(x T) int {
	return int(num.DivRoundBits(x, e.Parameters.LogQ()-e.Parameters.LogPolyDegree()-1+e.logLUTCount) << e.logLUTCount)
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *ManyLUTEvaluator[T]) BlindRotate(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *ManyLUTEvaluator[T]) BlindRotateAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.GLWECiphertext[T]) {
	switch {
	case e.Parameters.BlockSize() > 1:
		e.blindRotateBlockAssign(ct, lut, ctOut)
	default:
		e.blindRotateOriginalAssign(ct, lut, ctOut)
	}
}

// blindRotateBlockAssign computes the blind rotation when PolyDegree = LookUpTableSize and BlockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *ManyLUTEvaluator[T]) blindRotateBlockAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(e.Parameters.BlindRotateParameters())

	vec.CopyAssign(lut.Value, ctOut.Value[0].Coeffs)
	e.PolyEvaluator.MonomialMulPolyInPlace(ctOut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Parameters.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyAssign(ctOut.Value[0], e.Parameters.BlindRotateParameters(), polyDecomposed)
	for k := 0; k < e.Parameters.BlindRotateParameters().Level(); k++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][k])
	}

	e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc)
	e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[1]), e.buffer.fMono)
	e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)
	for j := 1; j < e.Parameters.BlockSize(); j++ {
		e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j].Value[0], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctBlockFourierAcc)
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[j+1]), e.buffer.fMono)
		e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)
	}

	for j := 0; j < e.Parameters.GLWERank()+1; j++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc.Value[j], ctOut.Value[j])
	}

	for i := 1; i < e.Parameters.BlockCount(); i++ {
		for j := 0; j < e.Parameters.GLWERank()+1; j++ {
			e.Decomposer.DecomposePolyAssign(ctOut.Value[j], e.Parameters.BlindRotateParameters(), polyDecomposed)
			for k := 0; k < e.Parameters.BlindRotateParameters().Level(); k++ {
				e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[j][k])
			}
		}

		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[i*e.Parameters.BlockSize()], e.buffer.ctAccFourierDecomposed, e.buffer.ctBlockFourierAcc)
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[i*e.Parameters.BlockSize()+1]), e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctBlockFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)
		for j := i*e.Parameters.BlockSize() + 1; j < (i+1)*e.Parameters.BlockSize(); j++ {
			e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[j], e.buffer.ctAccFourierDecomposed, e.buffer.ctBlockFourierAcc)
			e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[j+1]), e.buffer.fMono)
			e.FourierPolyMulAddFourierGLWEAssign(e.buffer.ctBlockFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)
		}

		for j := 0; j < e.Parameters.GLWERank()+1; j++ {
			e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc.Value[j], ctOut.Value[j])
		}
	}
}

// blindRotateOriginalAssign computes the blind rotation when PolyDegree = LookUpTableSize and BlockSize = 1.
// This is equivalent to the original blind rotation algorithm.
func (e *ManyLUTEvaluator[T]) blindRotateOriginalAssign(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut tfhe.GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(e.Parameters.BlindRotateParameters())

	vec.CopyAssign(lut.Value, ctOut.Value[0].Coeffs)
	e.PolyEvaluator.MonomialMulPolyInPlace(ctOut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Parameters.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyAssign(ctOut.Value[0], e.Parameters.BlindRotateParameters(), polyDecomposed)
	for k := 0; k < e.Parameters.BlindRotateParameters().Level(); k++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[0][k])
	}

	e.GadgetProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[0].Value[0], e.buffer.ctAccFourierDecomposed[0], e.buffer.ctFourierAcc)
	e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[1]), e.buffer.fMono)
	e.FourierPolyMulFourierGLWEAssign(e.buffer.ctFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)
	for j := 0; j < e.Parameters.GLWERank()+1; j++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc.Value[j], ctOut.Value[j])
	}

	for i := 1; i < e.Parameters.LWEDimension(); i++ {
		for j := 0; j < e.Parameters.GLWERank()+1; j++ {
			e.Decomposer.DecomposePolyAssign(ctOut.Value[j], e.Parameters.BlindRotateParameters(), polyDecomposed)
			for k := 0; k < e.Parameters.BlindRotateParameters().Level(); k++ {
				e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.ctAccFourierDecomposed[j][k])
			}
		}

		e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.BlindRotateKey.Value[i], e.buffer.ctAccFourierDecomposed, e.buffer.ctFourierAcc)
		e.PolyEvaluator.MonomialSubOneToFourierPolyAssign(-e.ModSwitch(ct.Value[i+1]), e.buffer.fMono)
		e.FourierPolyMulFourierGLWEAssign(e.buffer.ctFourierAcc, e.buffer.fMono, e.buffer.ctFourierAcc)

		for j := 0; j < e.Parameters.GLWERank()+1; j++ {
			e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierAcc.Value[j], ctOut.Value[j])
		}
	}
}
