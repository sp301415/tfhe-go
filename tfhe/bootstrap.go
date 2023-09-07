package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// LookUpTable is a trivially encrypted GLWE ciphertext that holds
// the lookup table for function evaluations during programmable bootstrapping.
type LookUpTable[T Tint] poly.Poly[T]

// NewLookUpTable allocates an empty lookup table.
func NewLookUpTable[T Tint](params Parameters[T]) LookUpTable[T] {
	return LookUpTable[T](poly.New[T](params.polyDegree))
}

// Copy returns a copy of the LUT.
func (lut LookUpTable[T]) Copy() LookUpTable[T] {
	return LookUpTable[T](poly.Poly[T](lut).Copy())
}

// CopyFrom copies values from a LUT.
func (lut *LookUpTable[T]) CopyFrom(lutIn LookUpTable[T]) {
	vec.CopyAssign(lutIn.Coeffs, lut.Coeffs)
}

// GenLookUpTable generates a lookup table based on function f and returns it.
// Inputs and Outputs of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTable(f func(int) int) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableAssign(f, lutOut)
	return lutOut
}

// GenLookUpTableAssign generates a lookup table based on function f and writes it to lutOut.
// Inputs and Outputs of f is cut by MessageModulus.
func (e *Evaluator[T]) GenLookUpTableAssign(f func(int) int, lutOut LookUpTable[T]) {
	boxSize := e.Parameters.polyDegree / int(e.Parameters.messageModulus)
	for x := 0; x < int(e.Parameters.messageModulus); x++ {
		fx := (T(f(x)) % e.Parameters.messageModulus) << e.Parameters.deltaLog
		for i := x * boxSize; i < (x+1)*boxSize; i++ {
			lutOut.Coeffs[i] = fx
		}
	}

	for i := 0; i < boxSize/2; i++ {
		lutOut.Coeffs[i] = -lutOut.Coeffs[i]
	}
	vec.RotateInPlace(lutOut.Coeffs, -boxSize/2)
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
	e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
	e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
	e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
}

// ModSwitch calculates round(2N * x / Q) mod 2N.
func (e *Evaluator[T]) ModSwitch(x T) int {
	return int(num.RoundRatioBits(x, e.Parameters.sizeT+e.Parameters.polyDegreeLog+1)) % (2 * e.Parameters.polyDegree)
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(e.Parameters.bootstrapParameters)

	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), -e.ModSwitch(ct.Value[0]), ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		ctOut.Value[i].Clear()
	}

	// Implementation of Algorithm 2 and Section 5.1 from https://eprint.iacr.org/2023/958.pdf
	for i := 0; i < e.Parameters.BlockCount(); i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.DecomposePolyAssign(ctOut.Value[j], polyDecomposed, e.Parameters.bootstrapParameters)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierTransformer.ToFourierPolyAssign(polyDecomposed[k], e.buffer.accDecomposed[j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductHoistedAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.accDecomposed, e.buffer.acc)
			e.MonomialMulMinusOneAddGLWEAssign(e.buffer.acc, -e.ModSwitch(ct.Value[j+1]), ctOut)
		}
	}
}

// SampleExtract extracts LWE ciphertext of index i from GLWE ciphertext and returns it.
// The output ciphertext has length GLWEDimension * PolyDegree + 1.
func (e *Evaluator[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.LargeLWEDimension())
	e.SampleExtractAssign(ct, index, ctOut)
	return ctOut
}

// SampleExtractAssign extracts LWE ciphertext of index from GLWE ciphertext.
// The output ciphertext should have length GLWEDimension * PolyDegree + 1.
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
func (e *Evaluator[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](ksk.OutputLWEDimension())
	e.KeySwitchAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchAssign switches key of ct, and saves it to ctOut.
func (e *Evaluator[T]) KeySwitchAssign(ct LWECiphertext[T], ksk KeySwitchKey[T], ctOut LWECiphertext[T]) {
	vecDecomposed := e.getVecDecomposedBuffer(ksk.decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.DecomposeAssign(ct.Value[i+1], vecDecomposed, ksk.decompParams)
		for j := 0; j < ksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.ScalarMulLWEAssign(ksk.Value[i].Value[j], vecDecomposed[j], ctOut)
			} else {
				e.ScalarMulAddLWEAssign(ksk.Value[i].Value[j], vecDecomposed[j], ctOut)
			}
		}
	}

	ctOut.Value[0] += ct.Value[0]
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext will be length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext should be length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	e.buffer.ctKeySwitch.Value[0] = 0
	vec.CopyAssign(ct.Value[e.Parameters.lweDimension+1:], e.buffer.ctKeySwitch.Value[1:])

	e.KeySwitchAssign(e.buffer.ctKeySwitch, e.EvaluationKey.KeySwitchKey, ctOut)
	vec.AddAssign(ctOut.Value, ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)
}
