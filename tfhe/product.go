package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// GadgetProduct calculates the gadget product between
// ctFourierGLev and p, and returns it.
func (e *Evaluator[T]) GadgetProduct(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.GadgetProductAssign(ctFourierGLev, p, ctOut)
	return ctOut
}

// GadgetProductAssign calculates the gadget product between
// ctFourierGLev and p, and writes it to ctOut.
func (e *Evaluator[T]) GadgetProductAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductAddAssign calculates the gadget product between
// ctFourierGLev and p, and adds it to ctOut.
func (e *Evaluator[T]) GadgetProductAddAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductSubAssign calculates the gadget product between
// ctFourierGLev and p, and subtracts it from ctOut.
func (e *Evaluator[T]) GadgetProductSubAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	polyFourierDecomposed := e.getPolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)
	e.FourierDecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyFourierDecomposed)

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductFourierDecomposedAssign calculates the gadget product between
// ctFourierGLev and fourier decomposed p, and writes it to ctOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductFourierDecomposedAddAssign calculates the gadget product between
// ctFourierGLev and fourier decomposed p, and adds it to ctOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAddAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductFourierDecomposedSubAssign calculates the gadget product between
// ctFourierGLev and fourier decomposed p, and subtracts it from ctOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedSubAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// ExternalProduct calculates the external product between
// ctFourierGGSW and ctGLWE, and returns it.
func (e *Evaluator[T]) ExternalProduct(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductAssign(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and adds it to ctOut.
func (e *Evaluator[T]) ExternalProductAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and subtracts it from ctOut.
func (e *Evaluator[T]) ExternalProductSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposed calculates the external product between
// ctFourierGGSW and fourier decomposed ctGLWE, and returns it.
func (e *Evaluator[T]) ExternalProductFourierDecomposed(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductFourierDecomposedAssign(ctFourierGGSW, ctGLWEDecomposed, ctOut)
	return ctOut
}

// ExternalProductFourierDecomposedAssign calculates the external product between
// ctFourierGGSW and fourier decomposed ctGLWE, and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], ctGLWEDecomposed[0][0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], ctGLWEDecomposed[0][j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedAddAssign calculates the external product between
// ctFourierGGSW and fourier decomposed ctGLWE, and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], ctGLWEDecomposed[0][0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], ctGLWEDecomposed[0][j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedSubAssign calculates the external product between
// ctFourierGGSW and fourier decomposed ctGLWE, and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], ctGLWEDecomposed[0][0], e.buffer.ctFourierProd)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], ctGLWEDecomposed[0][j], e.buffer.ctFourierProd)
	}

	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], e.buffer.ctFourierProd)
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// CMux calculates the mux gate between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctFourierGGSW * (ct1 - ct0).
// CMux essentially acts as an if clause; if ctFourierGGSW = 0, ct0 is returned, and if ctFourierGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMux(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.CMuxAssign(ctFourierGGSW, ct0, ct1, ctOut)
	return ctOut
}

// CMuxAssign calculates the mux gate between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctFourierGGSW * (ct1 - ct0).
// CMux essentially acts as an if clause; if ctFourierGGSW = 0, ct0 is returned, and if ctFourierGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMuxAssign(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1, ctOut GLWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	e.SubGLWEAssign(ct1, ct0, e.buffer.ctCMux)
	e.ExternalProductAddAssign(ctFourierGGSW, e.buffer.ctCMux, ctOut)
}
