package mktfhe

import (
	"sync"

	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with resepect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.BaseEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with resepect to given function and writes it to ctOut.
func (e *Evaluator[T]) BootstrapFuncAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.BaseEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *Evaluator[T]) BootstrapLUT(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *Evaluator[T]) BootstrapLUTAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut LWECiphertext[T]) {
	switch e.Parameters.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitch)
		e.BlindRotateAssign(e.buffer.ctKeySwitch, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// BootstrapFuncParallel returns a bootstrapped LWE ciphertext with resepect to given function in parallel.
func (e *Evaluator[T]) BootstrapFuncParallel(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.BaseEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUTParallel(ct, e.buffer.lut)
}

// BootstrapFuncParallelAssign bootstraps LWE ciphertext with resepect to given function and writes it to ctOut in parallel.
func (e *Evaluator[T]) BootstrapFuncParallelAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.BaseEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	e.BootstrapLUTAssign(ct, e.buffer.lut, ctOut)
}

// BootstrapLUTParallel returns a bootstrapped LWE ciphertext with respect to given LUT in parallel.
func (e *Evaluator[T]) BootstrapLUTParallel(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.BootstrapLUTParallelAssign(ct, lut, ctOut)
	return ctOut
}

// BootstrapLUTParallelAssign bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut in parallel.
func (e *Evaluator[T]) BootstrapLUTParallelAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut LWECiphertext[T]) {
	switch e.Parameters.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitch)
		e.BlindRotateParallelAssign(e.buffer.ctKeySwitch, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateParallelAssign(ct, lut, e.buffer.ctRotate)
		e.SampleExtractAssign(e.buffer.ctRotate, 0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign assigns the blind rotation of LWE ciphertext with respect to LUT to ctOut.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()
	e.BaseEvaluator.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), e.BaseEvaluator.ModSwitchNeg(ct.Value[0]), ctOut.Value[0])

	for i, ok := range e.PartyBitMap {
		if ok {
			e.buffer.ctRotateInputs[i].Value[0] = 0
			vec.CopyAssign(ct.Value[1+i*e.Parameters.SingleKeyDefaultLWEDimension():1+(i+1)*e.Parameters.SingleKeyDefaultLWEDimension()], e.buffer.ctRotateInputs[i].Value[1:])
			for j := 0; j < e.Parameters.accumulatorParameters.Level(); j++ {
				e.SingleKeyEvaluators[i].BlindRotateAssign(e.buffer.ctRotateInputs[i], e.buffer.gadgetLUTs[j], e.buffer.ctAccs[i])
				e.SingleKeyEvaluators[i].ToFourierGLWECiphertextAssign(e.buffer.ctAccs[i], e.buffer.ctFourierAccs[i].Value[j])
			}
			e.ExternalProductAssign(i, e.buffer.ctFourierAccs[i], ctOut, ctOut)
		}
	}
}

// BlindRotateParallel returns the blind rotation of LWE ciphertext with respect to LUT in parallel.
func (e *Evaluator[T]) BlindRotateParallel(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateParallelAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateParallelAssign assigns the blind rotation of LWE ciphertext with respect to LUT to ctOut in parallel.
func (e *Evaluator[T]) BlindRotateParallelAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()
	e.BaseEvaluator.PolyEvaluator.MonomialMulAssign(poly.Poly[T](lut), e.BaseEvaluator.ModSwitchNeg(ct.Value[0]), ctOut.Value[0])

	var wg sync.WaitGroup
	for i, ok := range e.PartyBitMap {
		if ok {
			wg.Add(1)
			go func(i int) {
				e.buffer.ctRotateInputs[i].Value[0] = 0
				vec.CopyAssign(ct.Value[1+i*e.Parameters.SingleKeyDefaultLWEDimension():1+(i+1)*e.Parameters.SingleKeyDefaultLWEDimension()], e.buffer.ctRotateInputs[i].Value[1:])
				for j := 0; j < e.Parameters.accumulatorParameters.Level(); j++ {
					e.SingleKeyEvaluators[i].BlindRotateAssign(e.buffer.ctRotateInputs[i], e.buffer.gadgetLUTs[j], e.buffer.ctAccs[i])
					e.SingleKeyEvaluators[i].ToFourierGLWECiphertextAssign(e.buffer.ctAccs[i], e.buffer.ctFourierAccs[i].Value[j])
				}
				wg.Done()
			}(i)
		}
	}
	wg.Wait()

	for i, ok := range e.PartyBitMap {
		if ok {
			e.ExternalProductAssign(i, e.buffer.ctFourierAccs[i], ctOut, ctOut)
		}
	}
}

// SampleExtract extracts LWE ciphertext of given index from GLWE ciphertext.
// The output ciphertext will be of dimension LWELargeDimension + 1,
// encrypted with LWELargeKey.
//
// Equivalent to GLWECiphertext.ToLWECiphertext.
func (e *Evaluator[T]) SampleExtract(ct GLWECiphertext[T], idx int) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.partyCount, e.Parameters.LWELargeDimension())
	e.SampleExtractAssign(ct, idx, ctOut)
	return ctOut
}

// SampleExtractAssign extracts LWE ciphertext of given index from GLWE ciphertext and writes it to ctOut.
// The output ciphertext should be of dimension LWELargeDimension + 1,
// and it will be a ciphertext encrypted with LWELargeKey.
func (e *Evaluator[T]) SampleExtractAssign(ct GLWECiphertext[T], idx int, ctOut LWECiphertext[T]) {
	ctOut.Value[0] = ct.Value[0].Coeffs[idx]

	ctMask, ctOutMask := ct.Value[1:], ctOut.Value[1:]
	for i := 0; i < e.Parameters.partyCount; i++ {
		start := i * e.Parameters.PolyDegree()
		end := (i + 1) * e.Parameters.PolyDegree()

		vec.ReverseAssign(ctMask[i].Coeffs, ctOutMask[start:end])

		vec.RotateInPlace(ctOutMask[start:end], idx+1)
		vec.NegAssign(ctOutMask[start+idx+1:end], ctOutMask[start+idx+1:end])
	}
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext will be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.partyCount, e.Parameters.SingleKeyLWEDimension())
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of dimension LWELargeDimension + 1.
// Output ciphertext should be of dimension LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	decomposed := e.BaseEvaluator.DecomposedBuffer(e.Parameters.Parameters.KeySwitchParameters())

	for i, ok := range e.PartyBitMap {
		ctMask := ct.Value[1+i*e.Parameters.SingleKeyLWELargeDimension() : 1+(i+1)*e.Parameters.SingleKeyLWELargeDimension()]
		ctOutMask := ctOut.Value[1+i*e.Parameters.SingleKeyLWEDimension() : 1+(i+1)*e.Parameters.SingleKeyLWEDimension()]
		if !ok {
			vec.Fill(ctOutMask, 0)
			continue
		}

		vec.CopyAssign(ctMask, ctOutMask)
		for j, jj := e.Parameters.SingleKeyLWEDimension(), 0; j < e.Parameters.SingleKeyLWELargeDimension(); j, jj = j+1, jj+1 {
			e.SingleKeyEvaluators[i].DecomposeAssign(ctMask[j], e.Parameters.Parameters.KeySwitchParameters(), decomposed)
			for k := 0; k < e.Parameters.Parameters.KeySwitchParameters().Level(); k++ {
				vec.ScalarMulAddAssign(e.EvaluationKeys[i].KeySwitchKey.Value[jj].Value[k].Value[1:], decomposed[k], ctOutMask)
				ctOut.Value[0] += decomposed[k] * e.EvaluationKeys[i].KeySwitchKey.Value[jj].Value[k].Value[0]
			}
		}
	}

	ctOut.Value[0] += ct.Value[0]
}
