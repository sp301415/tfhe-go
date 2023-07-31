package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// LookUpTable is a trivially encrypted GLWE ciphertext that holds
// the lookup table for function evaluations during programmable bootstrapping.
type LookUpTable[T Tint] GLWECiphertext[T]

// NewLookUpTable allocates an empty lookup table.
func NewLookUpTable[T Tint](params Parameters[T]) LookUpTable[T] {
	return LookUpTable[T](NewGLWECiphertext(params))
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	lutCopy := make([]poly.Poly[T], len(lut.Value))
	for i := range lutCopy {
		lutCopy[i] = lut.Value[i].Copy()
	}
	return LookUpTable[T]{Value: lutCopy}
}

// CopyFrom copies values from a LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	for i := range lut.Value {
		lut.Value[i].CopyFrom(lut.Value[i])
	}
}

// GenLookUpTable generates a lookup table based on function f and returns it.
// Inputs and Outputs of f is cut by MessageModulus.
func (e Evaluator[T]) GenLookUpTable(f func(int) int) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableAssign generates a lookup table based on function f and writes it to lutOut.
// Inputs and Outputs of f is cut by MessageModulus.
func (e Evaluator[T]) GenLookUpTableAssign(f func(int) int, lutOut LookUpTable[T]) {
	boxSize := e.Parameters.polyDegree / int(e.Parameters.messageModulus)
	for x := 0; x < int(e.Parameters.messageModulus); x++ {
		fx := (T(f(x)) % e.Parameters.messageModulus) << e.Parameters.deltaLog
		for i := x * boxSize; i < (x+1)*boxSize; i++ {
			lutOut.Value[0].Coeffs[i] = fx
		}
	}

	for i := 0; i < boxSize/2; i++ {
		lutOut.Value[0].Coeffs[i] = -lutOut.Value[0].Coeffs[i]
	}
	vec.RotateInPlace(lutOut.Value[0].Coeffs, -boxSize/2)
}

// GenLookUpTableFullAssign generates a lookup table based on function f and writes it to lutOut.
// Input of f is cut by MessageModulus, but output of f is encoded as-is.
func (e Evaluator[T]) GenLookUpTableFullAssign(f func(int) T, lutOut LookUpTable[T]) {
	boxSize := e.Parameters.polyDegree / int(e.Parameters.messageModulus)
	for x := 0; x < int(e.Parameters.messageModulus); x++ {
		fx := f(x)
		for i := x * boxSize; i < (x+1)*boxSize; i++ {
			lutOut.Value[0].Coeffs[i] = fx
		}
	}

	for i := 0; i < boxSize/2; i++ {
		lutOut.Value[0].Coeffs[i] = -lutOut.Value[0].Coeffs[i]
	}
	vec.RotateInPlace(lutOut.Value[0].Coeffs, -boxSize/2)
}

// Bootstrap returns a bootstrapped LWE ciphertext.
func (e Evaluator[T]) Bootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	return e.BootstrapFunc(ct, func(x int) int { return x })
}

// BootstrapAssign bootstraps LWE ciphertext and writes it to ctOut.
func (e Evaluator[T]) BootstrapAssign(ct, ctOut LWECiphertext[T]) {
	e.BootstrapFuncAssign(ct, func(x int) int { return x }, ctOut)
}

// BootstrapFunc returns a bootstrapped LWE ciphertext with resepect to given function.
func (e Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with resepect to given function and writes it to ctOut.
func (e Evaluator[T]) BootstrapFuncAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e Evaluator[T]) BootstrapLUT(ct LWECiphertext[T], lut LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e Evaluator[T]) BootstrapLUTAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut LWECiphertext[T]) {
	e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
	e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
	e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
}

// ModSwitch calculates round(2N * x / Q) mod 2N.
func (e Evaluator[T]) ModSwitch(x T) int {
	return int(num.RoundRatioBits(x, num.SizeT[T]()-(num.Log2(e.Parameters.polyDegree)+1))) % (2 * e.Parameters.polyDegree)
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(e.Parameters.bootstrapParameters)

	e.MonomialMulGLWEAssign(GLWECiphertext[T](lut), -e.ModSwitch(ct.Value[0]), ctOut)

	// Implementation of Algorithm 2 and Section 5.1 from https://eprint.iacr.org/2023/958.pdf
	for i := 0; i < e.Parameters.BlockCount(); i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.DecomposePolyAssign(ctOut.Value[j], buffDecomposed, e.Parameters.bootstrapParameters)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierTransformer.ToFourierPolyAssign(buffDecomposed[k], e.buffer.decompsedAcc[j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductHoistedAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.decompsedAcc, e.buffer.localAcc)
			e.SubGLWEAssign(ctOut, e.buffer.localAcc, ctOut)
			e.MonomialMulGLWEInPlace(e.buffer.localAcc, e.ModSwitch(ct.Value[j+1]))
			e.AddGLWEAssign(ctOut, e.buffer.localAcc, ctOut)
		}
	}
}

// SampleExtract extracts LWE ciphertext of index i from GLWE ciphertext and returns it.
// The output ciphertext has length GLWEDimension * PolyDegree + 1.
func (e Evaluator[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, e.Parameters.LargeLWEDimension())}
	e.SampleExtractAssign(ct, index, ctOut)
	return ctOut
}

// SampleExtractAssign extracts LWE ciphertext of index from GLWE ciphertext.
// The output ciphertext should have length GLWEDimension * PolyDegree + 1.
func (e Evaluator[T]) SampleExtractAssign(ct GLWECiphertext[T], index int, ctOut LWECiphertext[T]) {
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
func (e Evaluator[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchKey[T]) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, ksk.OutputLWEDimension()+1)}
	e.KeySwitchAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchAssign switches key of ct, and saves it to ctOut.
func (e Evaluator[T]) KeySwitchAssign(ct LWECiphertext[T], ksk KeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(ksk.decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.DecomposeAssign(ct.Value[i+1], buffDecomposed, ksk.decompParams)
		for j := 0; j < ksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.ScalarMulLWEAssign(ksk.Value[i].Value[j], -buffDecomposed[j], ctOut)
			} else {
				e.ScalarMulSubLWEAssign(ksk.Value[i].Value[j], buffDecomposed[j], ctOut)
			}
		}
	}

	ctOut.Value[0] += ct.Value[0]
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext will be length LWEDimension + 1.
func (e Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext should be length LWEDimension + 1.
func (e Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	e.buffer.ctKeySwitch.Value[0] = 0
	vec.CopyAssign(ct.Value[e.Parameters.lweDimension+1:], e.buffer.ctKeySwitch.Value[1:])

	e.KeySwitchAssign(e.buffer.ctKeySwitch, e.EvaluationKey.KeySwitchKey, ctOut)
	vec.AddAssign(ctOut.Value, ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)
}
