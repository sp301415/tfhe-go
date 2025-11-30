package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// GenLUT generates a lookup table based on function f.
// Input and output of f is cut by MessageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUT(f []func(int) int) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLUT(e.Params.baseParams)
	e.GenLUTTo(lutOut, f)
	return lutOut
}

// GenLUTTo generates a lookup table based on function f and writes it to lutOut.
// Input and output of f is cut by MessageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTTo(lutOut tfhe.LookUpTable[T], f []func(int) int) {
	e.GenLUTCustomTo(lutOut, f, e.Params.baseParams.MessageModulus(), e.Params.baseParams.Scale())
}

// GenLUTFull generates a lookup table based on function f.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTFull(f []func(int) T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLUT(e.Params.baseParams)
	e.GenLUTFullTo(lutOut, f)
	return lutOut
}

// GenLUTFullTo generates a lookup table based on function f and writes it to lutOut.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTFullTo(lutOut tfhe.LookUpTable[T], f []func(int) T) {
	e.GenLUTCustomFullTo(lutOut, f, e.Params.baseParams.MessageModulus())
}

// GenLUTCustom generates a lookup table based on function f using custom messageModulus and scale.
// Input and output of f is cut by messageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTCustom(f []func(int) int, messageModulus, scale T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLUT(e.Params.baseParams)
	e.GenLUTCustomTo(lutOut, f, messageModulus, scale)
	return lutOut
}

// GenLUTCustomTo generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Input and output of f is cut by messageModulus.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTCustomTo(lutOut tfhe.LookUpTable[T], f []func(int) int, messageModulus, scale T) {
	ff := make([]func(int) T, len(f))
	for i := range f {
		j := i
		ff[i] = func(x int) T { return e.EncodeLWECustom(f[j](x), messageModulus, scale).Value }
	}
	e.GenLUTCustomFullTo(lutOut, ff, messageModulus)
}

// GenLUTCustomFull generates a lookup table based on function f using custom messageModulus.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTCustomFull(f []func(int) T, messageModulus T) tfhe.LookUpTable[T] {
	lutOut := tfhe.NewLUT(e.Params.baseParams)
	e.GenLUTCustomFullTo(lutOut, f, messageModulus)
	return lutOut
}

// GenLUTCustomFullTo generates a lookup table based on function f using custom messageModulus and scale and writes it to lutOut.
// Output of f is encoded as-is.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) GenLUTCustomFullTo(lutOut tfhe.LookUpTable[T], f []func(int) T, messageModulus T) {
	if len(f) > e.Params.lutCount {
		panic("GenLUTCustomFullTo: Number of functions exceeds LUTCount")
	}

	y := make([]T, e.Params.lutCount)

	for x := 0; x < int(messageModulus); x++ {
		start := num.DivRound(x*e.Params.baseParams.LUTSize(), int(messageModulus))
		end := num.DivRound((x+1)*e.Params.baseParams.LUTSize(), int(messageModulus))
		for i := range f {
			y[i] = f[i](x)
		}
		for xx := start; xx < end; xx += e.Params.lutCount {
			for i := 0; i < e.Params.lutCount; i++ {
				lutOut.Value[0].Coeffs[xx+i] = y[i]
			}
		}
	}

	offset := num.DivRound(e.Params.baseParams.LUTSize(), int(2*messageModulus))
	vec.RotateInPlace(lutOut.Value[0].Coeffs, -offset)
	for i := e.Params.baseParams.LUTSize() - offset; i < e.Params.baseParams.LUTSize(); i++ {
		lutOut.Value[0].Coeffs[i] = -lutOut.Value[0].Coeffs[i]
	}
}

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
//
// Panics if len(f) > LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapFunc(ct tfhe.LWECiphertext[T], f []func(int) int) []tfhe.LWECiphertext[T] {
	e.GenLUTTo(e.buf.lut, f)
	return e.BootstrapLUT(ct, e.buf.lut)
}

// BootstrapFuncTo bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
//
// Panics if len(f) > LUTCount.
// If len(ctOut) > LUTCount, only the first LUTCount elements are written.
// Panics if len(ctOut) < LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapFuncTo(ctOut []tfhe.LWECiphertext[T], ct tfhe.LWECiphertext[T], f []func(int) int) {
	e.GenLUTTo(e.buf.lut, f)
	e.BootstrapLUTTo(ctOut, ct, e.buf.lut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *ManyLUTEvaluator[T]) BootstrapLUT(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) []tfhe.LWECiphertext[T] {
	ctOut := make([]tfhe.LWECiphertext[T], e.Params.lutCount)
	for i := 0; i < e.Params.lutCount; i++ {
		ctOut[i] = tfhe.NewLWECiphertext(e.Params.baseParams)
	}
	e.BootstrapLUTTo(ctOut, ct, lut)
	return ctOut
}

// BootstrapLUTTo bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
//
// If len(ctOut) > LUTCount, only the first LUTCount elements are written.
// Panics if len(ctOut) < LUTCount.
func (e *ManyLUTEvaluator[T]) BootstrapLUTTo(ctOut []tfhe.LWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	switch e.Params.baseParams.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.DefaultKeySwitchTo(e.buf.ctKeySwitch, ct)
		e.BlindRotateTo(e.buf.ctRotate, e.buf.ctKeySwitch, lut)
		for i := 0; i < e.Params.lutCount; i++ {
			e.buf.ctRotate.AsLWECiphertextTo(i, ctOut[i])
		}
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateTo(e.buf.ctRotate, ct, lut)
		for i := 0; i < e.Params.lutCount; i++ {
			e.buf.ctRotate.AsLWECiphertextTo(i, e.buf.ctExtract)
			e.DefaultKeySwitchTo(ctOut[i], e.buf.ctExtract)
		}
	}
}

// ModSwitch switches the modulus of x from Q to 2 * LUTSize.
func (e *ManyLUTEvaluator[T]) ModSwitch(x T) int {
	return int(num.DivRoundBits(x, e.Params.baseParams.LogQ()-e.Params.baseParams.LogPolyRank()-1+e.Params.logLUTCount) << e.Params.logLUTCount)
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *ManyLUTEvaluator[T]) BlindRotate(ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) tfhe.GLWECiphertext[T] {
	ctOut := tfhe.NewGLWECiphertext(e.Params.baseParams)
	e.BlindRotateTo(ctOut, ct, lut)
	return ctOut
}

// BlindRotateTo computes the blind rotation of LWE ciphertext with respect to LUT, and writes it to ctOut.
func (e *ManyLUTEvaluator[T]) BlindRotateTo(ctOut tfhe.GLWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	switch {
	case e.Params.baseParams.BlockSize() > 1:
		e.blindRotateBlockTo(ctOut, ct, lut)
	default:
		e.blindRotateOriginalTo(ctOut, ct, lut)
	}
}

// blindRotateBlockTo computes the blind rotation when PolyRank = LUTSize and BlockSize > 1.
// This is equivalent to the blind rotation algorithm using block binary keys, as explained in https://eprint.iacr.org/2023/958.
func (e *ManyLUTEvaluator[T]) blindRotateBlockTo(ctOut tfhe.GLWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	pDcmp := e.Decomposer.PolyBuffer(e.Params.baseParams.BlindRotateParams())

	e.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Params.baseParams.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[0], e.Params.baseParams.BlindRotateParams())
	for k := 0; k < e.Params.baseParams.BlindRotateParams().Level(); k++ {
		e.PolyEvaluator.FwdFFTPolyTo(e.buf.ctFFTAccDcmp[0][k], pDcmp[k])
	}

	e.GadgetProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[0].Value[0], e.buf.ctFFTAccDcmp[0])
	e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[1]))
	e.FFTPolyMulFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)
	for j := 1; j < e.Params.baseParams.BlockSize(); j++ {
		e.GadgetProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[j].Value[0], e.buf.ctFFTAccDcmp[0])
		e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[j+1]))
		e.FFTPolyMulAddFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)
	}

	for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.ctFFTAcc.Value[j])
	}

	for i := 1; i < e.Params.baseParams.BlockCount(); i++ {
		for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
			e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[j], e.Params.baseParams.BlindRotateParams())
			for k := 0; k < e.Params.baseParams.BlindRotateParams().Level(); k++ {
				e.PolyEvaluator.FwdFFTPolyTo(e.buf.ctFFTAccDcmp[j][k], pDcmp[k])
			}
		}

		e.ExternalProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[i*e.Params.baseParams.BlockSize()], e.buf.ctFFTAccDcmp)
		e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[i*e.Params.baseParams.BlockSize()+1]))
		e.FFTPolyMulFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)
		for j := i*e.Params.baseParams.BlockSize() + 1; j < (i+1)*e.Params.baseParams.BlockSize(); j++ {
			e.ExternalProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[j], e.buf.ctFFTAccDcmp)
			e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[j+1]))
			e.FFTPolyMulAddFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)
		}

		for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
			e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.ctFFTAcc.Value[j])
		}
	}
}

// blindRotateOriginalTo computes the blind rotation when PolyRank = LUTSize and BlockSize = 1.
// This is equivalent to the original blind rotation algorithm.
func (e *ManyLUTEvaluator[T]) blindRotateOriginalTo(ctOut tfhe.GLWECiphertext[T], ct tfhe.LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	pDcmp := e.Decomposer.PolyBuffer(e.Params.baseParams.BlindRotateParams())

	e.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.ModSwitch(ct.Value[0]))
	for i := 1; i < e.Params.baseParams.GLWERank()+1; i++ {
		ctOut.Value[i].Clear()
	}

	e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[0], e.Params.baseParams.BlindRotateParams())
	for k := 0; k < e.Params.baseParams.BlindRotateParams().Level(); k++ {
		e.PolyEvaluator.FwdFFTPolyTo(e.buf.ctFFTAccDcmp[0][k], pDcmp[k])
	}

	e.GadgetProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[0].Value[0], e.buf.ctFFTAccDcmp[0])
	e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[1]))
	e.FFTPolyMulFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)
	for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.ctFFTAcc.Value[j])
	}

	for i := 1; i < e.Params.baseParams.LWEDimension(); i++ {
		for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
			e.Decomposer.DecomposePolyTo(pDcmp, ctOut.Value[j], e.Params.baseParams.BlindRotateParams())
			for k := 0; k < e.Params.baseParams.BlindRotateParams().Level(); k++ {
				e.PolyEvaluator.FwdFFTPolyTo(e.buf.ctFFTAccDcmp[j][k], pDcmp[k])
			}
		}

		e.ExternalProdFFTGLWETo(e.buf.ctFFTBlockAcc, e.EvalKey.BlindRotateKey.Value[i], e.buf.ctFFTAccDcmp)
		e.PolyEvaluator.MonomialSubOneFwdFFTTo(e.buf.fMono, -e.ModSwitch(ct.Value[i+1]))
		e.FFTPolyMulFFTGLWETo(e.buf.ctFFTAcc, e.buf.ctFFTBlockAcc, e.buf.fMono)

		for j := 0; j < e.Params.baseParams.GLWERank()+1; j++ {
			e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[j], e.buf.ctFFTAcc.Value[j])
		}
	}
}
