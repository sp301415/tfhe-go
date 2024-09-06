package mktfhe

import (
	"sync"

	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.BaseSingleKeyEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUT(ct, e.buffer.lut)
}

// BootstrapFuncAssign bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *Evaluator[T]) BootstrapFuncAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.BaseSingleKeyEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
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
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateAssign(ct, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// BootstrapFuncParallel returns a bootstrapped LWE ciphertext with respect to given function in parallel.
func (e *Evaluator[T]) BootstrapFuncParallel(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.BaseSingleKeyEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
	return e.BootstrapLUTParallel(ct, e.buffer.lut)
}

// BootstrapFuncParallelAssign bootstraps LWE ciphertext with respect to given function and writes it to ctOut in parallel.
func (e *Evaluator[T]) BootstrapFuncParallelAssign(ct LWECiphertext[T], f func(int) int, ctOut LWECiphertext[T]) {
	e.BaseSingleKeyEvaluator.GenLookUpTableAssign(f, e.buffer.lut)
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
		e.buffer.ctRotate.ToLWECiphertextAssign(0, ctOut)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateParallelAssign(ct, lut, e.buffer.ctRotate)
		e.buffer.ctRotate.ToLWECiphertextAssign(0, e.buffer.ctExtract)
		e.KeySwitchForBootstrapAssign(e.buffer.ctExtract, ctOut)
	}
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateAssign computes the blind rotation of LWE ciphertext with respect to LUT and writes it to ctOut.
func (e *Evaluator[T]) BlindRotateAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()

	vec.CopyAssign(lut.Value, ctOut.Value[0].Coeffs)
	e.BaseSingleKeyEvaluator.PolyEvaluator.MonomialMulInPlace(ctOut.Value[0], -e.BaseSingleKeyEvaluator.ModSwitch(ct.Value[0]))
	for i, ok := range e.PartyBitMap {
		if ok {
			e.buffer.ctRotateInputs[i].Value[0] = 0
			vec.CopyAssign(ct.Value[1+i*e.Parameters.SingleKeyLWEDimension():1+(i+1)*e.Parameters.SingleKeyLWEDimension()], e.buffer.ctRotateInputs[i].Value[1:])
			for j := 0; j < e.Parameters.accumulatorParameters.Level(); j++ {
				e.SingleKeyEvaluators[i].BlindRotateAssign(e.buffer.ctRotateInputs[i], e.buffer.gadgetLUTs[j], e.buffer.ctAccs[i])
				e.SingleKeyEvaluators[i].ToFourierGLWECiphertextAssign(e.buffer.ctAccs[i], e.buffer.ctFourierAccs[i].Value[j])
			}
			e.ExternalProductGLWEAssign(i, e.buffer.ctFourierAccs[i], ctOut, ctOut)
		}
	}
}

// BlindRotateParallel returns the blind rotation of LWE ciphertext with respect to LUT in parallel.
func (e *Evaluator[T]) BlindRotateParallel(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.BlindRotateParallelAssign(ct, lut, ctOut)
	return ctOut
}

// BlindRotateParallelAssign computes the blind rotation of LWE ciphertext with respect to LUT and writes it to ctOut in parallel.
func (e *Evaluator[T]) BlindRotateParallelAssign(ct LWECiphertext[T], lut tfhe.LookUpTable[T], ctOut GLWECiphertext[T]) {
	ctOut.Clear()

	vec.CopyAssign(lut.Value, ctOut.Value[0].Coeffs)
	e.BaseSingleKeyEvaluator.PolyEvaluator.MonomialMulInPlace(ctOut.Value[0], -e.BaseSingleKeyEvaluator.ModSwitch(ct.Value[0]))

	var wg sync.WaitGroup
	for i, ok := range e.PartyBitMap {
		if ok {
			wg.Add(1)
			go func(i int) {
				e.buffer.ctRotateInputs[i].Value[0] = 0
				vec.CopyAssign(ct.Value[1+i*e.Parameters.SingleKeyLWEDimension():1+(i+1)*e.Parameters.SingleKeyLWEDimension()], e.buffer.ctRotateInputs[i].Value[1:])
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
			e.ExternalProductGLWEAssign(i, e.buffer.ctFourierAccs[i], ctOut, ctOut)
		}
	}
}

// KeySwitchForBootstrap performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext will be of length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrap(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Parameters.SingleKeyLWEDimension())
	e.KeySwitchForBootstrapAssign(ct, ctOut)
	return ctOut
}

// KeySwitchForBootstrapAssign performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext should be of length LWEDimension + 1.
func (e *Evaluator[T]) KeySwitchForBootstrapAssign(ct, ctOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.ScalarDecomposedBuffer(e.Parameters.KeySwitchParameters())

	ctOut.Value[0] = ct.Value[0]

	for i, ok := range e.PartyBitMap {
		ctMask := ct.Value[1+i*e.Parameters.SingleKeyGLWEDimension() : 1+(i+1)*e.Parameters.SingleKeyGLWEDimension()]
		ctOutMask := ctOut.Value[1+i*e.Parameters.SingleKeyLWEDimension() : 1+(i+1)*e.Parameters.SingleKeyLWEDimension()]
		if ok {
			vec.CopyAssign(ctMask, ctOutMask)
			for j, jj := e.Parameters.SingleKeyLWEDimension(), 0; j < e.Parameters.SingleKeyGLWEPartialDimension(); j, jj = j+1, jj+1 {
				e.SingleKeyEvaluators[i].DecomposeScalarAssign(ctMask[j], e.Parameters.KeySwitchParameters(), scalarDecomposed)
				for k := 0; k < e.Parameters.KeySwitchParameters().Level(); k++ {
					vec.ScalarMulAddAssign(e.EvaluationKeys[i].KeySwitchKey.Value[jj].Value[k].Value[1:], scalarDecomposed[k], ctOutMask)
					ctOut.Value[0] += scalarDecomposed[k] * e.EvaluationKeys[i].KeySwitchKey.Value[jj].Value[k].Value[0]
				}
			}
		} else {
			vec.Fill(ctOutMask, 0)
		}
	}
}
