package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// HybridProductGLWE returns the hybrid product between ctFourierUniEnc and ctGLWE.
func (e *Evaluator[T]) HybridProductGLWE(idx int, ctFourierUniEnc FourierUniEncryption[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.HybridProductGLWEAssign(idx, ctFourierUniEnc, ctGLWE, ctOut)
	return ctOut
}

// HybridProductGLWEAssign computes the hybrid product between ctFourierUniEnc and ctGLWE and writes it to ctGLWEOut.
func (e *Evaluator[T]) HybridProductGLWEAssign(idx int, ctFourierUniEnc FourierUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	polyDecomposed := e.polyDecomposedBuffer(ctFourierUniEnc.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierUniEnc.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[0])
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
	}

	eIdx.FourierEvaluator.MulAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[0].Value[1], polyFourierDecomposed[0], e.buffer.ctFourierProdSingle)
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
	}
	eIdx.FourierEvaluator.NegAssign(e.buffer.ctFourierProdSingle, e.buffer.ctFourierProdSingle)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.DecomposePolyAssign(ctGLWE.Value[i+1], ctFourierUniEnc.GadgetParameters, polyDecomposed)
			for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
			}

			eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[i+1])
			for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[i+1])
			}

			for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[i].CRSPublicKey.Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
			}
		}
	}

	eIdx.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProdSingle, e.buffer.ctProdSingle)
	e.DecomposePolyAssign(e.buffer.ctProdSingle, ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[j], polyFourierDecomposed[j])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[1+idx])
	}

	eIdx.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i+1], ctGLWEOut.Value[i+1])
		} else {
			ctGLWEOut.Value[i+1].Clear()
		}
	}
}

// HybridProductAssign computes the hybrid product between ctFourierUniEnc and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) HybridProductAddGLWEAssign(idx int, ctFourierUniEnc FourierUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	polyDecomposed := e.polyDecomposedBuffer(ctFourierUniEnc.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierUniEnc.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[0])
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
	}

	eIdx.FourierEvaluator.MulAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[0].Value[1], polyFourierDecomposed[0], e.buffer.ctFourierProdSingle)
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
	}
	eIdx.FourierEvaluator.NegAssign(e.buffer.ctFourierProdSingle, e.buffer.ctFourierProdSingle)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.DecomposePolyAssign(ctGLWE.Value[i+1], ctFourierUniEnc.GadgetParameters, polyDecomposed)
			for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
			}

			eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[i+1])
			for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[i+1])
			}

			for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[i].CRSPublicKey.Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
			}
		}
	}

	eIdx.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProdSingle, e.buffer.ctProdSingle)
	e.DecomposePolyAssign(e.buffer.ctProdSingle, ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[j], polyFourierDecomposed[j])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[1+idx])
	}

	eIdx.FourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.FourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i+1], ctGLWEOut.Value[i+1])
		}
	}
}

// HybridProductSubGLWEAssign computes the hybrid product between ctFourierUniEnc and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) HybridProductSubGLWEAssign(idx int, ctFourierUniEnc FourierUniEncryption[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	polyDecomposed := e.polyDecomposedBuffer(ctFourierUniEnc.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierUniEnc.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[0])
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
	}

	eIdx.FourierEvaluator.MulAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[0].Value[1], polyFourierDecomposed[0], e.buffer.ctFourierProdSingle)
	for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[idx].CRSPublicKey.Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
	}
	eIdx.FourierEvaluator.NegAssign(e.buffer.ctFourierProdSingle, e.buffer.ctFourierProdSingle)

	for i, ok := range e.PartyBitMap {
		if ok {
			e.DecomposePolyAssign(ctGLWE.Value[i+1], ctFourierUniEnc.GadgetParameters, polyDecomposed)
			for i := 0; i < ctFourierUniEnc.GadgetParameters.Level(); i++ {
				e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
			}

			eIdx.FourierEvaluator.MulAssign(ctFourierUniEnc.Value[0].Value[0].Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd.Value[i+1])
			for j := 1; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[0].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[i+1])
			}

			for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
				eIdx.FourierEvaluator.MulAddAssign(e.EvaluationKeys[i].CRSPublicKey.Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProdSingle)
			}
		}
	}

	eIdx.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProdSingle, e.buffer.ctProdSingle)
	e.DecomposePolyAssign(e.buffer.ctProdSingle, ctFourierUniEnc.GadgetParameters, polyDecomposed)
	for j := 0; j < ctFourierUniEnc.GadgetParameters.Level(); j++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[j], polyFourierDecomposed[j])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[0], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[0])
		eIdx.FourierEvaluator.MulAddAssign(ctFourierUniEnc.Value[1].Value[j].Value[1], polyFourierDecomposed[j], e.buffer.ctFourierProd.Value[1+idx])
	}

	eIdx.FourierEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.FourierEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i+1], ctGLWEOut.Value[i+1])
		}
	}
}

// ExternalProductGLWE returns the external product between ctFourierGLev and ctGLWE.
func (e *Evaluator[T]) ExternalProductGLWE(idx int, ctFourierGLev tfhe.FourierGLevCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductGLWEAssign(idx, ctFourierGLev, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductGLWEAssign computes the external product between ctFourierGLev and ctGLWE and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductGLWEAssign(idx int, ctFourierGLev tfhe.FourierGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[0], e.buffer.ctRelinTransposed[0])
	e.buffer.ctRelin.Value[0].CopyFrom(e.buffer.ctRelinTransposed[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[i+1], e.buffer.ctRelinTransposed[i+1])
			e.buffer.ctRelin.Value[i+1].CopyFrom(e.buffer.ctRelinTransposed[i+1].Value[1])
		}
	}

	e.HybridProductGLWEAssign(idx, e.EvaluationKeys[idx].RelinKey, e.buffer.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[0], e.buffer.ctRelinTransposed[0].Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[i+1], e.buffer.ctRelinTransposed[i+1].Value[0], ctGLWEOut.Value[i+1])
		}
	}
}

// ExternalProductAddGLWEAssign computes the external product between ctFourierGLev and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddGLWEAssign(idx int, ctFourierGLev tfhe.FourierGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[0], e.buffer.ctRelinTransposed[0])
	e.buffer.ctRelin.Value[0].CopyFrom(e.buffer.ctRelinTransposed[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[i+1], e.buffer.ctRelinTransposed[i+1])
			e.buffer.ctRelin.Value[i+1].CopyFrom(e.buffer.ctRelinTransposed[i+1].Value[1])
		}
	}

	e.HybridProductAddGLWEAssign(idx, e.EvaluationKeys[idx].RelinKey, e.buffer.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[0], e.buffer.ctRelinTransposed[0].Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[i+1], e.buffer.ctRelinTransposed[i+1].Value[0], ctGLWEOut.Value[i+1])
		}
	}
}

// ExternalProductSubGLWEAssign computes the external product between ctFourierGLev and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubGLWEAssign(idx int, ctFourierGLev tfhe.FourierGLevCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	eIdx := e.SingleKeyEvaluators[idx]

	eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[0], e.buffer.ctRelinTransposed[0])
	e.buffer.ctRelin.Value[0].CopyFrom(e.buffer.ctRelinTransposed[0].Value[1])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.GadgetProductAssignGLWE(ctFourierGLev, ctGLWE.Value[i+1], e.buffer.ctRelinTransposed[i+1])
			e.buffer.ctRelin.Value[i+1].CopyFrom(e.buffer.ctRelinTransposed[i+1].Value[1])
		}
	}

	e.HybridProductSubGLWEAssign(idx, e.EvaluationKeys[idx].RelinKey, e.buffer.ctRelin, ctGLWEOut)

	eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[0], e.buffer.ctRelinTransposed[0].Value[0], ctGLWEOut.Value[0])
	for i, ok := range e.PartyBitMap {
		if ok {
			eIdx.PolyEvaluator.AddAssign(ctGLWEOut.Value[i+1], e.buffer.ctRelinTransposed[i+1].Value[0], ctGLWEOut.Value[i+1])
		}
	}
}
