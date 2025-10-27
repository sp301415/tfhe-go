package mktfhe

import (
	"sync"

	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BootstrapFunc returns a bootstrapped LWE ciphertext with respect to given function.
func (e *Evaluator[T]) BootstrapFunc(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.subEvaluator.GenLUTTo(e.buf.lut, f)
	return e.BootstrapLUT(ct, e.buf.lut)
}

// BootstrapFuncTo bootstraps LWE ciphertext with respect to given function and writes it to ctOut.
func (e *Evaluator[T]) BootstrapFuncTo(ctOut, ct LWECiphertext[T], f func(int) int) {
	e.subEvaluator.GenLUTTo(e.buf.lut, f)
	e.BootstrapLUTTo(ctOut, ct, e.buf.lut)
}

// BootstrapLUT returns a bootstrapped LWE ciphertext with respect to given LUT.
func (e *Evaluator[T]) BootstrapLUT(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.BootstrapLUTTo(ctOut, ct, lut)
	return ctOut
}

// BootstrapLUTTo bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut.
func (e *Evaluator[T]) BootstrapLUTTo(ctOut, ct LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	switch e.Params.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.DefaultKeySwitchTo(e.buf.ctKeySwitc, ct)
		e.BlindRotateTo(e.buf.ctRotate, e.buf.ctKeySwitc, lut)
		e.buf.ctRotate.AsLWECiphertextTo(ctOut, 0)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateTo(e.buf.ctRotate, ct, lut)
		e.buf.ctRotate.AsLWECiphertextTo(e.buf.ctExtract, 0)
		e.DefaultKeySwitchTo(ctOut, e.buf.ctExtract)
	}
}

// BootstrapFuncParallel returns a bootstrapped LWE ciphertext with respect to given function in parallel.
func (e *Evaluator[T]) BootstrapFuncParallel(ct LWECiphertext[T], f func(int) int) LWECiphertext[T] {
	e.subEvaluator.GenLUTTo(e.buf.lut, f)
	return e.BootstrapLUTParallel(ct, e.buf.lut)
}

// BootstrapFuncParallelTo bootstraps LWE ciphertext with respect to given function and writes it to ctOut in parallel.
func (e *Evaluator[T]) BootstrapFuncParallelTo(ctOut, ct LWECiphertext[T], f func(int) int) {
	e.subEvaluator.GenLUTTo(e.buf.lut, f)
	e.BootstrapLUTParallelTo(ctOut, ct, e.buf.lut)
}

// BootstrapLUTParallel returns a bootstrapped LWE ciphertext with respect to given LUT in parallel.
func (e *Evaluator[T]) BootstrapLUTParallel(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.BootstrapLUTParallelTo(ctOut, ct, lut)
	return ctOut
}

// BootstrapLUTParallelTo bootstraps LWE ciphertext with respect to given LUT and writes it to ctOut in parallel.
func (e *Evaluator[T]) BootstrapLUTParallelTo(ctOut, ct LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	switch e.Params.BootstrapOrder() {
	case tfhe.OrderKeySwitchBlindRotate:
		e.DefaultKeySwitchTo(e.buf.ctKeySwitc, ct)
		e.BlindRotateParallelTo(e.buf.ctRotate, e.buf.ctKeySwitc, lut)
		e.buf.ctRotate.AsLWECiphertextTo(ctOut, 0)
	case tfhe.OrderBlindRotateKeySwitch:
		e.BlindRotateParallelTo(e.buf.ctRotate, ct, lut)
		e.buf.ctRotate.AsLWECiphertextTo(e.buf.ctExtract, 0)
		e.DefaultKeySwitchTo(ctOut, e.buf.ctExtract)
	}
}

// BlindRotate returns the blind rotation of LWE ciphertext with respect to LUT.
func (e *Evaluator[T]) BlindRotate(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.BlindRotateTo(ctOut, ct, lut)
	return ctOut
}

// BlindRotateTo computes the blind rotation of LWE ciphertext with respect to LUT and writes it to ctOut.
func (e *Evaluator[T]) BlindRotateTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	ctOut.Clear()

	e.subEvaluator.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.subEvaluator.ModSwitch(ct.Value[0]))
	for i, ok := range e.PartyBitMap {
		if ok {
			e.buf.ctRotateIn[i].Value[0] = 0
			copy(e.buf.ctRotateIn[i].Value[1:], ct.Value[1+i*e.Params.subParams.LWEDimension():1+(i+1)*e.Params.subParams.LWEDimension()])
			for j := 0; j < e.Params.accumulatorParams.Level(); j++ {
				e.SubEvaluators[i].BlindRotateTo(e.buf.ctAccs[i], e.buf.ctRotateIn[i], e.gadgetLUTs[j])
				e.SubEvaluators[i].FFTGLWECiphertextTo(e.buf.fctAccs[i].Value[j], e.buf.ctAccs[i])
			}
			e.ExternalProdGLWETo(i, e.buf.fctAccs[i], ctOut, ctOut)
		}
	}
}

// BlindRotateParallel returns the blind rotation of LWE ciphertext with respect to LUT in parallel.
func (e *Evaluator[T]) BlindRotateParallel(ct LWECiphertext[T], lut tfhe.LookUpTable[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.BlindRotateParallelTo(ctOut, ct, lut)
	return ctOut
}

// BlindRotateParallelTo computes the blind rotation of LWE ciphertext with respect to LUT and writes it to ctOut in parallel.
func (e *Evaluator[T]) BlindRotateParallelTo(ctOut GLWECiphertext[T], ct LWECiphertext[T], lut tfhe.LookUpTable[T]) {
	ctOut.Clear()

	e.subEvaluator.PolyEvaluator.MonomialMulPolyTo(ctOut.Value[0], lut.Value[0], -e.subEvaluator.ModSwitch(ct.Value[0]))

	var wg sync.WaitGroup
	for i, ok := range e.PartyBitMap {
		if ok {
			wg.Add(1)
			go func(i int) {
				e.buf.ctRotateIn[i].Value[0] = 0
				copy(e.buf.ctRotateIn[i].Value[1:], ct.Value[1+i*e.Params.subParams.LWEDimension():1+(i+1)*e.Params.subParams.LWEDimension()])
				for j := 0; j < e.Params.accumulatorParams.Level(); j++ {
					e.SubEvaluators[i].BlindRotateTo(e.buf.ctAccs[i], e.buf.ctRotateIn[i], e.gadgetLUTs[j])
					e.SubEvaluators[i].FFTGLWECiphertextTo(e.buf.fctAccs[i].Value[j], e.buf.ctAccs[i])
				}
				wg.Done()
			}(i)
		}
	}
	wg.Wait()

	for i, ok := range e.PartyBitMap {
		if ok {
			e.ExternalProdGLWETo(i, e.buf.fctAccs[i], ctOut, ctOut)
		}
	}
}

// DefaultKeySwitch performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext will be of length LWEDimension + 1.
func (e *Evaluator[T]) DefaultKeySwitch(ct LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertextCustom[T](e.Params.LWEDimension())
	e.DefaultKeySwitchTo(ctOut, ct)
	return ctOut
}

// DefaultKeySwitchTo performs the keyswitching using evaulater's evaluation key.
// Input ciphertext should be of length GLWEDimension + 1.
// Output ciphertext should be of length LWEDimension + 1.
func (e *Evaluator[T]) DefaultKeySwitchTo(ctOut LWECiphertext[T], ct LWECiphertext[T]) {
	cDcmp := e.Decomposer.ScalarBuffer(e.Params.KeySwitchParams())

	ctOut.Value[0] = ct.Value[0]

	for i, ok := range e.PartyBitMap {
		ctMask := ct.Value[1+i*e.Params.subParams.GLWEDimension() : 1+(i+1)*e.Params.subParams.GLWEDimension()]
		ctOutMask := ctOut.Value[1+i*e.Params.subParams.LWEDimension() : 1+(i+1)*e.Params.subParams.LWEDimension()]
		if ok {
			copy(ctOutMask, ctMask)
			for j, jj := e.Params.subParams.LWEDimension(), 0; j < e.Params.subParams.GLWEDimension(); j, jj = j+1, jj+1 {
				e.SubEvaluators[i].Decomposer.DecomposeScalarTo(cDcmp, ctMask[j], e.Params.KeySwitchParams())
				for k := 0; k < e.Params.KeySwitchParams().Level(); k++ {
					vec.ScalarMulAddTo(ctOutMask, e.EvalKey[i].KeySwitchKey.Value[jj].Value[k].Value[1:], cDcmp[k])
					ctOut.Value[0] += cDcmp[k] * e.EvalKey[i].KeySwitchKey.Value[jj].Value[k].Value[0]
				}
			}
		} else {
			vec.Fill(ctOutMask, 0)
		}
	}
}
