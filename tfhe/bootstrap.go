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
	// We calculate f(round(P*j/2N)), where P = messageModulus * 2 (We use 1-bit padding, remember?)
	// For x := round(p*j/2N), observe that:
	// x = 1 => j = N/p ~ 3N/p
	// x = 2 => j = 3N/p ~ 5N/p
	// ...
	// The only exception is when x = 0. In this case,
	// x = 0 => j = 0 ~ N/p and j = -N/p ~ 0.
	// So we can rotate negacyclically for N/p.

	intMessageMod := int(e.Parameters.messageModulus)
	boxSize := e.Parameters.polyDegree / intMessageMod // 2N/P
	for x := 0; x < intMessageMod; x++ {
		fx := (T(f(x)) % e.Parameters.messageModulus) << e.Parameters.deltaLog
		for i := x * boxSize; i < (x+1)*boxSize; i++ {
			lutOut.Value[0].Coeffs[i] = fx
		}
	}

	// rotate left negacycically.
	for i := 0; i < boxSize/2; i++ {
		lutOut.Value[0].Coeffs[i] = -lutOut.Value[0].Coeffs[i]
	}
	vec.RotateAssign(lutOut.Value[0].Coeffs, -boxSize/2)
}

// Bootstrap returns a bootstrapped LWE ciphertext.
func (e Evaluater[T]) Bootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	return e.BootstrapFunc(ct, func(x int) int { return x })
}

// BootstrapInPlace bootstraps LWE ciphertext and writes it to ctOut.
func (e Evaluater[T]) BootstrapInPlace(ct, ctOut LWECiphertext[T]) {
	e.BootstrapFuncInPlace(ct, func(x int) int { return x }, ctOut)
}

// BootstrapAssign bootstraps LWE cipehrtext and overwrites it.
func (e Evaluater[T]) BootstrapAssign(ct LWECiphertext[T]) {
	e.BootstrapFuncAssign(ct, func(x int) int { return x })
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

// BootstrapFuncAssign bootstraps LWE cipehrtext with resepect to given function and overwrites it.
func (e Evaluater[T]) BootstrapFuncAssign(ct LWECiphertext[T], f func(int) int) {
	e.GenLookUpTableInPlace(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e Evaluater[T]) BootstrapLUT(ct LWECiphertext[T], lut LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTInPlace(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTInPlace bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e Evaluater[T]) BootstrapLUTInPlace(ct LWECiphertext[T], lut LookUpTable[T], ctOut LWECiphertext[T]) {
	e.BlindRotateInPlace(ct, lut, e.buffer.blindRotatedCtForBootstrap)
	e.SampleExtractInPlace(e.buffer.blindRotatedCtForBootstrap, 0, e.buffer.sampleExtractedCtForBootstrap)
	e.KeySwitchForBootstrapInPlace(e.buffer.sampleExtractedCtForBootstrap, ctOut)
}

// BootstrapLUTAssign bootstraps LWE cipehrtext with respect to given LUT and overwrites it.
func (e Evaluater[T]) BootstrapLUTAssign(ct LWECiphertext[T], lut LookUpTable[T]) {
	e.BlindRotateInPlace(ct, lut, e.buffer.blindRotatedCtForBootstrap)
	e.SampleExtractInPlace(e.buffer.blindRotatedCtForBootstrap, 0, e.buffer.sampleExtractedCtForBootstrap)
	e.KeySwitchForBootstrapInPlace(e.buffer.sampleExtractedCtForBootstrap, ct)
}

// Note that the encoded LUT only considers inputs between 0 and MessageModulus.
// ModSwitch calculates round(2N * p / Q).
func (e Evaluater[T]) ModSwitch(p T) int {
	return int(num.RoundRatioBits(p, num.SizeT[T]()-(num.Log2(e.Parameters.polyDegree)+1)))
}

// BlindRotate calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluater[T]) BlindRotate(ct LWECiphertext[T], lut LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateInPlace(ct, lut, ctOut)
	return ctOut
}

// BlindRotateInPlace calculates the blind rotation of LWE ciphertext with respect to LUT.
func (e Evaluater[T]) BlindRotateInPlace(ct LWECiphertext[T], lut LookUpTable[T], ctOut GLWECiphertext[T]) {
	// c = X^-b * LUT
	e.MonomialDivGLWEInPlace(GLWECiphertext[T](lut), e.ModSwitch(ct.Value[0]), ctOut)

	// c <- CMUX(bsk[i], c, X^ai * c)
	for i := 0; i < e.Parameters.lweDimension; i++ {
		e.MonomialMulGLWEInPlace(ctOut, e.ModSwitch(ct.Value[i+1]), e.buffer.rotatedCtForBlindRotate)
		e.CMuxFourierAssign(e.evaluationKey.BootstrapKey.Value[i], ctOut, e.buffer.rotatedCtForBlindRotate)
	}
}

// SampleExtract extracts LWE ciphertext of index i from GLWE ciphertext and returns it.
// The output ciphertext has length GLWEDimension * PolyDegree + 1.
func (e Evaluater[T]) SampleExtract(ct GLWECiphertext[T], index int) LWECiphertext[T] {
	ctOut := LWECiphertext[T]{Value: make([]T, e.Parameters.glweDimension*e.Parameters.polyDegree+1)}
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

		// Reverse polynomial coefficient of ctMask, and save it to ctOutMask
		vec.ReverseInPlace(ctMask[i].Coeffs, ctOutMask[start:end])

		// We rotate to right index + 1 times,
		// and negate index+1 ~ PolyDegree values.
		vec.RotateAssign(ctOutMask[start:end], index+1)
		vec.NegAssign(ctOutMask[start+index+1 : end])
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
				vec.ScalarMulInPlace(ksk.Value[i].Value[j].Value, -buffDecomposed[j], ctOut.Value)
			} else {
				vec.ScalarMulSubAssign(ksk.Value[i].Value[j].Value, buffDecomposed[j], ctOut.Value)
			}
		}
	}

	ctOut.Value[0] += ct.Value[0]
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's bootstrapping key.
// Input ciphertext should be length GLWEDimension + 1, and output ciphertext will be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	return e.KeySwitch(ct, e.evaluationKey.KeySwitchKey)
}

// KeySwitchForBootstrapInPlace performs the keyswitching using evaulater's bootstrapping key.
// Input ciphertext should be length GLWEDimension + 1, and output ciphertext should be length LWEDimension + 1.
func (e Evaluater[T]) KeySwitchForBootstrapInPlace(ct, ctOut LWECiphertext[T]) {
	e.KeySwitchInPlace(ct, e.evaluationKey.KeySwitchKey, ctOut)
}
