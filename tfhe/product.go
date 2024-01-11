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
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(polyFourierDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(polyFourierDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductAddAssign computes the gadget product between p and ctFourierGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAddAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(polyFourierDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(polyFourierDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductSubAssign computes the gadget product between p and ctFourierGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProductSubAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(polyFourierDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(polyFourierDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductFourierDecomposedAssign computes the gadget product between fourier decomposed p and ctFourierGLev and writes it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(pDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(pDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductFourierDecomposedAddAssign computes the gadget product between fourier decomposed p and ctFourierGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAddAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(pDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(pDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductFourierDecomposedSubAssign computes the gadget product between fourier decomposed p and ctFourierGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedSubAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(pDecomposed[0], ctFourierGLev.Value[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(pDecomposed[i], ctFourierGLev.Value[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
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
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(polyDecomposed[0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddAssign computes the external product between ctFourierGGSW and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(polyDecomposed[0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubAssign computes the external product between ctFourierGGSW and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(polyDecomposed[0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(polyDecomposed[j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposed returns the external product between ctFourierGGSW and fourier decomposed ctGLWE.
func (e *Evaluator[T]) ExternalProductFourierDecomposed(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductFourierDecomposedAssign(ctFourierGGSW, ctGLWEDecomposed, ctOut)
	return ctOut
}

// ExternalProductFourierDecomposedAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctGLWEDecomposed[0][0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[0][j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[i][j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedAddAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctGLWEDecomposed[0][0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[0][j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[i][j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedSubAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctGLWEDecomposed[0][0], ctFourierGGSW.Value[0].Value[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[0][j], ctFourierGGSW.Value[0].Value[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctGLWEDecomposed[i][j], ctFourierGGSW.Value[i].Value[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
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
