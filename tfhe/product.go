package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// GadgetProduct returns the gadget product between p and ctFourierGLev.
func (e *Evaluator[T]) GadgetProduct(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.GadgetProductAssign(ctFourierGLev, p, ctOut)
	return ctOut
}

// GadgetProductAssign computes the gadget product between p and ctFourierGLev and writes it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductAddAssign computes the gadget product between p and ctFourierGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAddAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductSubAssign computes the gadget product between p and ctFourierGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProductSubAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductFourierDecomposedFourierAssign computes the gadget product between fourier decomposed p and ctFourierGLev and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedFourierAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], ctFourierGLWEOut)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierDecomposedAddFourierAssign computes the gadget product between fourier decomposed p and ctFourierGLev and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAddFourierAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierDecomposedSubFourierAssign computes the gadget product between fourier decomposed p and ctFourierGLev and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedSubFourierAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulSubFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// ExternalProduct returns the external product between ctFourierGGSW and ctGLWE.
func (e *Evaluator[T]) ExternalProduct(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductAssign(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductAssign computes the external product between ctFourierGGSW and ctGLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProductAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddAssign computes the external product between ctFourierGGSW and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubAssign computes the external product between ctFourierGGSW and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.FourierEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedFourierAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], ctGLWEDecomposed[0][0], ctFourierGLWEOut)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], ctGLWEDecomposed[0][j], ctFourierGLWEOut)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductFourierDecomposedAddFourierAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAddFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductFourierDecomposedSubFourierAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedSubFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulSubFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], ctFourierGLWEOut)
		}
	}
}

// CMux returns the mux gate between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctFourierGGSW * (ct1 - ct0).
// CMux essentially acts as an if clause; if ctFourierGGSW = 0, ct0 is returned, and if ctFourierGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMux(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.CMuxAssign(ctFourierGGSW, ct0, ct1, ctOut)
	return ctOut
}

// CMuxAssign computes the mux gate between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctFourierGGSW * (ct1 - ct0) and writes it to ctOut.
// CMux essentially acts as an if clause; if ctFourierGGSW = 0, ct0 is returned, and if ctFourierGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMuxAssign(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1, ctOut GLWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	e.SubGLWEAssign(ct1, ct0, e.buffer.ctCMux)
	e.ExternalProductAddAssign(ctFourierGGSW, e.buffer.ctCMux, ctOut)
}
