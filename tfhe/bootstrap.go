package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
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
	boxSize := 1 << (e.Parameters.polyDegreeLog - e.Parameters.messageModulusLog)
	for x := 0; x < 1<<e.Parameters.messageModulusLog; x++ {
		y := e.EncodeLWE(f(x)).Value
		for xx := x * boxSize; xx < (x+1)*boxSize; xx++ {
			lutOut.Coeffs[xx] = y
		}
	}
	e.PolyEvaluator.MonomialMulInPlace(poly.Poly[T](lutOut), -boxSize/2)
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
	boxSize := 1 << (e.Parameters.polyDegreeLog - e.Parameters.messageModulusLog)
	for x := 0; x < 1<<e.Parameters.messageModulusLog; x++ {
		y := f(x)
		for xx := x * boxSize; xx < (x+1)*boxSize; xx++ {
			lutOut.Coeffs[xx] = y
		}
	}
	e.PolyEvaluator.MonomialMulInPlace(poly.Poly[T](lutOut), -boxSize/2)
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
	e.KeySwitchForBootstrapAssign(ct, e.buffer.ctSmall)
	e.BlindRotateAssign(e.buffer.ctSmall, lut, e.buffer.ctRotate)
	e.SampleExtractAssign(e.buffer.ctRotate, 0, ctOut)
}

// ModSwitch calculates round(2N * x / Q) mod 2N.
func (e *Evaluator[T]) ModSwitch(x T) int {
	return int(num.RoundRatioBits(x, e.Parameters.sizeT-(e.Parameters.polyDegreeLog+1))) % (2 * e.Parameters.polyDegree)
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()

	// Allocate buffer ourselves, so that we can reuse them explicitly.
	polyDecomposed := e.getPolyDecomposedBuffer(e.Parameters.bootstrapParameters)

	// Implementation of Algorithm 2 and Section 5.1 from https://eprint.iacr.org/2023/958
	e.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), -e.ModSwitch(ct.Value[0]), ctOut.Value[0])

	e.DecomposePolyAssign(ctOut.Value[0], e.Parameters.bootstrapParameters, polyDecomposed)
	for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.accDecomposed[0][k])
	}

	for j := 0; j < e.Parameters.blockSize; j++ {
		e.GadgetProductFourierDecomposedAssign(e.EvaluationKey.BootstrapKey.Value[j].Value[0], e.buffer.accDecomposed[0], e.buffer.acc)
		e.MonomialMulMinusOneAddGLWEAssign(e.buffer.acc, -e.ModSwitch(ct.Value[j+1]), ctOut)
	}

	for i := 1; i < e.Parameters.BlockCount(); i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.DecomposePolyAssign(ctOut.Value[j], e.Parameters.bootstrapParameters, polyDecomposed)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[k], e.buffer.accDecomposed[j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductFourierDecomposedAssign(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.accDecomposed, e.buffer.acc)
			e.MonomialMulMinusOneAddGLWEAssign(e.buffer.acc, -e.ModSwitch(ct.Value[j+1]), ctOut)
		}
	}
}

// SampleExtract extracts LWE ciphertext of given index from GLWE ciphertext and returns it.
func (e *Evaluator[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweDimension)
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
// Output ciphertext will be of dimension LWESmallDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.lweSmallDimension)
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's bootstrap key.
// Output ciphertext should be of dimension LWESmallDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	vec.CopyAssign(ct.Value[:e.Parameters.lweSmallDimension+1], ctOut.Value)

	decomposed := e.getDecomposedBuffer(e.Parameters.keyswitchParameters)

	for i, ii := e.Parameters.lweSmallDimension, 0; i < e.Parameters.lweDimension; i, ii = i+1, ii+1 {
		e.DecomposeAssign(ct.Value[i+1], e.Parameters.keyswitchParameters, decomposed)
		for j := 0; j < e.Parameters.keyswitchParameters.level; j++ {
			e.ScalarMulAddLWEAssign(e.EvaluationKey.KeySwitchKey.Value[ii].Value[j], decomposed[j], ctOut)
		}
	}
}
