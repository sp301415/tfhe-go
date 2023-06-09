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
func (e Evaluater[T]) GenLookUpTable(f func(int) int) LookUpTable[T] {
	lutOut := NewLookUpTable(e.Parameters)
	e.GenLookUpTableInPlace(f, lutOut)
	return lutOut
}

// GenLookUpTableInPlace generates a lookup table based on function f and writes it to lutOut.
// Inputs and Outputs of f is cut by MessageModulus.
func (e Evaluater[T]) GenLookUpTableInPlace(f func(int) int, lutOut LookUpTable[T]) {
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
	vec.RotateInPlace(lutOut.Value[0].Coeffs, -boxSize/2, lutOut.Value[0].Coeffs)
}

// GenLookUpTableFullInPlace generates a lookup table based on function f and writes it to lutOut.
// Input of f is cut by MessageModulus, but output of f is encoded as-is.
func (e Evaluater[T]) GenLookUpTableFullInPlace(f func(int) T, lutOut LookUpTable[T]) {
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
	vec.RotateInPlace(lutOut.Value[0].Coeffs, -boxSize/2, lutOut.Value[0].Coeffs)
}

// Bootstrap returns a bootstrapped LWE ciphertext.
func (e Evaluater[T]) Bootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	return e.BootstrapFunc(ct, func(x int) int { return x })
}

// BootstrapInPlace bootstraps LWE ciphertext and writes it to ctOut.
func (e Evaluater[T]) BootstrapInPlace(ct, ctOut LWECiphertext[T]) {
	e.BootstrapFuncInPlace(ct, func(x int) int { return x }, ctOut)
}

// BootstrapFunc returns a bootstrapped LWE ciphertext with resepect to given function.
func (e Evaluater[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.GenLookUpTableInPlace(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncInPlace bootstraps LWE ciphertext with resepect to given function and writes it to ctOut.
func (e Evaluater[T]) BootstrapFuncInPlace(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.GenLookUpTableInPlace(f, e.buffer.lut)
	e.BootstrapLUTInPlace(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e Evaluater[T]) BootstrapLUT(ct LWECiphertext[T], lut LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTInPlace(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTInPlace bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e Evaluater[T]) BootstrapLUTInPlace(ct LWECiphertext[T], lut LookUpTable[T], ctOut LWECiphertext[T]) {
	e.BlindRotateInPlace(ct, lut, e.buffer.blindRotatedCt)
	e.SampleExtractInPlace(e.buffer.blindRotatedCt, 0, e.buffer.sampleExtractedCt)
	e.KeySwitchForBootstrapInPlace(e.buffer.sampleExtractedCt, ctOut)
}

// ModSwitch calculates round(2N * x / Q).
func (e Evaluater[T]) ModSwitch(x T) int {
	return int(num.RoundRatioBits(x, num.SizeT[T]()-(num.Log2(e.Parameters.polyDegree)+1)))
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluater[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateInPlace(ct, lut, ctOut)
	return ctOut
}

// BlindRotateInPlace calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluater[T]) BlindRotateInPlace(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(e.Parameters.bootstrapParameters)

	e.MonomialDivGLWEInPlace(GLWECiphertext[T](lut), e.ModSwitch(ct.Value[0]), ctOut)

	// Implementation of Algorithm 2 and Section 5.1 from https://eprint.iacr.org/2023/958.pdf
	for i := 0; i < e.Parameters.BlockCount(); i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.DecomposePolyInplace(ctOut.Value[j], buffDecomposed, e.Parameters.bootstrapParameters)
			for k := 0; k < e.Parameters.bootstrapParameters.level; k++ {
				e.FourierTransformer.ToFourierPolyInPlace(buffDecomposed[k], e.buffer.decompsedAcc[j][k])
			}
		}

		for j := i * e.Parameters.blockSize; j < (i+1)*e.Parameters.blockSize; j++ {
			e.ExternalProductFourierHoistedInPlace(e.EvaluationKey.BootstrapKey.Value[j], e.buffer.decompsedAcc, e.buffer.localAcc)
			e.SubGLWEInPlace(ctOut, e.buffer.localAcc, ctOut)
			e.MonomialMulGLWEInPlace(e.buffer.localAcc, e.ModSwitch(ct.Value[j+1]), e.buffer.localAcc)
			e.AddGLWEInPlace(ctOut, e.buffer.localAcc, ctOut)
		}
	}
}

// SampleExtract extracts LWE ciphertext of index i from GLWE ciphertext and returns it.
// The output ciphertext has length GLWEDimension * PolyDegree + 1.
func (e Evaluater[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, e.Parameters.LargeLWEDimension())}
	e.SampleExtractInPlace(ct, index, ctOut)
	return ctOut
}

// SampleExtractInPlace extracts LWE ciphertext of index from GLWE ciphertext.
// The output ciphertext should have length GLWEDimension * PolyDegree + 1.
func (e Evaluater[T]) SampleExtractInPlace(ct GLWECiphertext[T], index int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[index]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < e.Parameters.glweDimension; i++ {
		start := i * e.Parameters.polyDegree
		end := (i + 1) * e.Parameters.polyDegree

		vec.ReverseInPlace(ctMask[i].Coeffs, ctOutMask[start:end])

		vec.RotateInPlace(ctOutMask[start:end], index+1, ctOutMask[start:end])
		vec.NegInPlace(ctOutMask[start+index+1:end], ctOutMask[start+index+1:end])
	}
}

// KeySwitch switches key of ct, and returns a new ciphertext.
func (e Evaluater[T]) KeySwitch(ct LWECiphertext[T], ksk KeySwitchKey[T]) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, ksk.OutputLWEDimension()+1)}
	e.KeySwitchInPlace(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchInPlace switches key of ct, and saves it to ctOut.
func (e Evaluater[T]) KeySwitchInPlace(ct LWECiphertext[T], ksk KeySwitchKey[T], ctOut LWECiphertext[T]) {
	buffDecomposed := e.decomposedVecBuffer(ksk.decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.DecomposeInPlace(ct.Value[i+1], buffDecomposed, ksk.decompParams)
		for j := 0; j < ksk.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.ScalarMulLWEInPlace(ksk.Value[i].Value[j], -buffDecomposed[j], ctOut)
			} else {
				e.ScalarMulSubLWEInPlace(ksk.Value[i].Value[j], buffDecomposed[j], ctOut)
			}
		}
	}

	ctOut.Value[0] += ct.Value[0]
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext will be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.KeySwitchForBootstrapInPlace(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapInPlace performs the keyswitching using evaulater's bootstrap key.
// Input ciphertext should be length LWELargeDimension + 1, and output ciphertext should be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrapInPlace(ct, ctOut LWECiphertext[T]) {
	e.buffer.leftoverCt.Value[0] = 0
	vec.CopyInPlace(ct.Value[e.Parameters.lweDimension+1:], e.buffer.leftoverCt.Value[1:])

	e.KeySwitchInPlace(e.buffer.leftoverCt, e.EvaluationKey.KeySwitchKey, ctOut)
	vec.AddInPlace(ctOut.Value, ct.Value[:e.Parameters.lweDimension+1], ctOut.Value)
}
