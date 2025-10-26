package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// HybridProdGLWE returns the hybrid product between ctFFTUniEnc and ctGLWE.
func (e *Evaluator[T]) HybridProdGLWE(idx int, ctFFTUniEnc FFTUniEncryption[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.HybridProdGLWETo(idx, ctFFTUniEnc, ctGLWE, ctOut)
	return ctOut
}

// HybridProdGLWETo computes the hybrid product between ctFFTUniEnc and ctGLWE and writes it to ctGLWEOut.
func (e *Evaluator[T]) HybridProdGLWETo(idx int, ctFFTUniEnc FFTUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	pDcmp := e.Decomposer.PolyBuffer(ctFFTUniEnc.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTUniEnc.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTUniEnc.GadgetParams)
	for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[0].Value[1], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[j].Value[1], fpDcmp[j])
	}
	eIdx.PolyEvaluator.NegFFTPolyTo(e.buf.sfctProd, e.buf.sfctProd)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i+1], ctFFTUniEnc.GadgetParams)
			for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
				e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
			}

			eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
			for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
			}

			for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[i].CRSPublicKey.Value[j].Value[0], fpDcmp[j])
			}
		}
	}

	eIdx.PolyEvaluator.InvFFTToUnsafe(e.buf.sctProd, e.buf.sfctProd)
	e.Decomposer.DecomposePolyTo(pDcmp, e.buf.sctProd, ctFFTUniEnc.GadgetParams)
	for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		e.PolyEvaluator.FFTTo(fpDcmp[j], pDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[1].Value[j].Value[0], fpDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[1+idx], ctFFTUniEnc.Value[1].Value[j].Value[1], fpDcmp[j])
	}

	eIdx.PolyEvaluator.InvFFTToUnsafe(ctGLWEOut.Value[0], e.buf.fctProd.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.InvFFTToUnsafe(ctGLWEOut.Value[i+1], e.buf.fctProd.Value[i+1])
		} else {
			ctGLWEOut.Value[i+1].Clear()
		}
	}
}

// HybridProdAddGLWETo computes the hybrid product between ctFFTUniEnc and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) HybridProdAddGLWETo(idx int, ctFFTUniEnc FFTUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	pDcmp := e.Decomposer.PolyBuffer(ctFFTUniEnc.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTUniEnc.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTUniEnc.GadgetParams)
	for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[0].Value[1], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[j].Value[1], fpDcmp[j])
	}
	eIdx.PolyEvaluator.NegFFTPolyTo(e.buf.sfctProd, e.buf.sfctProd)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i+1], ctFFTUniEnc.GadgetParams)
			for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
				e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
			}

			eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
			for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
			}

			for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[i].CRSPublicKey.Value[j].Value[0], fpDcmp[j])
			}
		}
	}

	eIdx.PolyEvaluator.InvFFTToUnsafe(e.buf.sctProd, e.buf.sfctProd)
	e.Decomposer.DecomposePolyTo(pDcmp, e.buf.sctProd, ctFFTUniEnc.GadgetParams)
	for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		e.PolyEvaluator.FFTTo(fpDcmp[j], pDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[1].Value[j].Value[0], fpDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[1+idx], ctFFTUniEnc.Value[1].Value[j].Value[1], fpDcmp[j])
	}

	eIdx.PolyEvaluator.InvFFTAddToUnsafe(ctGLWEOut.Value[0], e.buf.fctProd.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.InvFFTAddToUnsafe(ctGLWEOut.Value[i+1], e.buf.fctProd.Value[i+1])
		}
	}
}

// HybridProdSubGLWETo computes the hybrid product between ctFFTUniEnc and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) HybridProdSubGLWETo(idx int, ctFFTUniEnc FFTUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	pDcmp := e.Decomposer.PolyBuffer(ctFFTUniEnc.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTUniEnc.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTUniEnc.GadgetParams)
	for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
	}

	eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[0].Value[1], fpDcmp[0])
	for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[idx].CRSPublicKey.Value[j].Value[1], fpDcmp[j])
	}
	eIdx.PolyEvaluator.NegFFTPolyTo(e.buf.sfctProd, e.buf.sfctProd)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i+1], ctFFTUniEnc.GadgetParams)
			for i := 0; i < ctFFTUniEnc.GadgetParams.Level(); i++ {
				e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
			}

			eIdx.PolyEvaluator.MulFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[0].Value[0], fpDcmp[0])
			for j := 1; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[i+1], ctFFTUniEnc.Value[0].Value[j].Value[0], fpDcmp[j])
			}

			for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
				eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.sfctProd, e.EvalKey[i].CRSPublicKey.Value[j].Value[0], fpDcmp[j])
			}
		}
	}

	eIdx.PolyEvaluator.InvFFTToUnsafe(e.buf.sctProd, e.buf.sfctProd)
	e.Decomposer.DecomposePolyTo(pDcmp, e.buf.sctProd, ctFFTUniEnc.GadgetParams)
	for j := 0; j < ctFFTUniEnc.GadgetParams.Level(); j++ {
		e.PolyEvaluator.FFTTo(fpDcmp[j], pDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[0], ctFFTUniEnc.Value[1].Value[j].Value[0], fpDcmp[j])
		eIdx.PolyEvaluator.MulAddFFTPolyTo(e.buf.fctProd.Value[1+idx], ctFFTUniEnc.Value[1].Value[j].Value[1], fpDcmp[j])
	}

	eIdx.PolyEvaluator.InvFFTSubToUnsafe(ctGLWEOut.Value[0], e.buf.fctProd.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.InvFFTSubToUnsafe(ctGLWEOut.Value[i+1], e.buf.fctProd.Value[i+1])
		}
	}
}

// ExternalProductGLWE returns the external product between ctFFTGLev and ctGLWE.
func (e *Evaluator[T]) ExternalProductGLWE(idx int, ctFFTGLev tfhe.FFTGLevCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.ExternalProductGLWETo(idx, ctFFTGLev, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductGLWETo computes the external product between ctFFTGLev and ctGLWE and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductGLWETo(idx int, ctFFTGLev tfhe.FFTGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	eIdx.GadgetProdGLWETo(e.buf.ctRelinT[0], ctFFTGLev, ctGLWE.Value[0])
	e.buf.ctRelin.Value[0].CopyFrom(e.buf.ctRelinT[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProdGLWETo(e.buf.ctRelinT[i+1], ctFFTGLev, ctGLWE.Value[i+1])
			e.buf.ctRelin.Value[i+1].CopyFrom(e.buf.ctRelinT[i+1].Value[1])
		}
	}

	e.HybridProdGLWETo(idx, e.EvalKey[idx].RelinKey, e.buf.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[0], ctGLWEOut.Value[0], e.buf.ctRelinT[0].Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[i+1], ctGLWEOut.Value[i+1], e.buf.ctRelinT[i+1].Value[0])
		}
	}
}

// ExternalProductAddGLWETo computes the external product between ctFFTGLev and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddGLWETo(idx int, ctFFTGLev tfhe.FFTGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	eIdx.GadgetProdGLWETo(e.buf.ctRelinT[0], ctFFTGLev, ctGLWE.Value[0])
	e.buf.ctRelin.Value[0].CopyFrom(e.buf.ctRelinT[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProdGLWETo(e.buf.ctRelinT[i+1], ctFFTGLev, ctGLWE.Value[i+1])
			e.buf.ctRelin.Value[i+1].CopyFrom(e.buf.ctRelinT[i+1].Value[1])
		}
	}

	e.HybridProdAddGLWETo(idx, e.EvalKey[idx].RelinKey, e.buf.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[0], ctGLWEOut.Value[0], e.buf.ctRelinT[0].Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[i+1], ctGLWEOut.Value[i+1], e.buf.ctRelinT[i+1].Value[0])
		}
	}
}

// ExternalProductSubGLWETo computes the external product between ctFFTGLev and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubGLWETo(idx int, ctFFTGLev tfhe.FFTGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SubEvaluators[idx]

	eIdx.GadgetProdGLWETo(e.buf.ctRelinT[0], ctFFTGLev, ctGLWE.Value[0])
	e.buf.ctRelin.Value[0].CopyFrom(e.buf.ctRelinT[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProdGLWETo(e.buf.ctRelinT[i+1], ctFFTGLev, ctGLWE.Value[i+1])
			e.buf.ctRelin.Value[i+1].CopyFrom(e.buf.ctRelinT[i+1].Value[1])
		}
	}

	e.HybridProdSubGLWETo(idx, e.EvalKey[idx].RelinKey, e.buf.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[0], ctGLWEOut.Value[0], e.buf.ctRelinT[0].Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddPolyTo(ctGLWEOut.Value[i+1], ctGLWEOut.Value[i+1], e.buf.ctRelinT[i+1].Value[0])
		}
	}
}
