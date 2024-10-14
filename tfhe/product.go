package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GadgetProductLWE returns the gadget product between c and ctLev.
func (e *Evaluator[T]) GadgetProductLWE(ctLev LevCiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.GadgetProductLWEAssign(ctLev, c, ctOut)
	return ctOut
}

// GadgetProductLWEAssign computes the gadget product between c and ctLev and writes it to ctLWEOut.
func (e *Evaluator[T]) GadgetProductLWEAssign(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.ScalarDecomposedBuffer(ctLev.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(c, ctLev.GadgetParameters, scalarDecomposed)
	vec.ScalarMulAssign(ctLev.Value[0].Value, scalarDecomposed[0], ctLWEOut.Value)
	for i := 1; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulAddAssign(ctLev.Value[i].Value, scalarDecomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductAddLWEAssign computes the gadget product between c and ctLev and adds it to ctLWEOut.
func (e *Evaluator[T]) GadgetProductAddLWEAssign(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.ScalarDecomposedBuffer(ctLev.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(c, ctLev.GadgetParameters, scalarDecomposed)
	for i := 0; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulAddAssign(ctLev.Value[i].Value, scalarDecomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductSubLWEAssign computes the gadget product between c and ctLev and subtracts it from ctLWEOut.
func (e *Evaluator[T]) GadgetProductSubLWEAssign(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.ScalarDecomposedBuffer(ctLev.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(c, ctLev.GadgetParameters, scalarDecomposed)
	for i := 0; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulSubAssign(ctLev.Value[i].Value, scalarDecomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductGLWE returns the gadget product between p and ctFourierGLev.
func (e *Evaluator[T]) GadgetProductGLWE(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.GadgetProductGLWEAssign(ctFourierGLev, p, ctOut)
	return ctOut
}

// GadgetProductGLWEAssign computes the gadget product between p and ctFourierGLev and writes it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.Decomposer.PolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctProdFourierGLWE)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctProdFourierGLWE)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductAddGLWEAssign computes the gadget product between p and ctFourierGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAddGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.Decomposer.PolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctProdFourierGLWE)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctProdFourierGLWE)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductSubGLWEAssign computes the gadget product between p and ctFourierGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProductSubGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.Decomposer.PolyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctProdFourierGLWE)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctProdFourierGLWE)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolySubAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductFourierDecomposedFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], ctFourierGLWEOut)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierDecomposedAddFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedAddFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierDecomposedSubFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierDecomposedSubFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulSubFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// ExternalProductLWE returns the external product between ctGSW and ctLWE.
func (e *Evaluator[T]) ExternalProductLWE(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ExternalProductLWEAssign(ctGSW, ctLWE, ctOut)
	return ctOut
}

// ExternalProductLWEAssign computes the external product between ctGSW and ctLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProductLWEAssign(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T], ctLWEOut LWECiphertext[T]) {
	decomposed := e.Decomposer.ScalarDecomposedBuffer(ctGSW.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(ctLWE.Value[0], ctGSW.GadgetParameters, decomposed)
	vec.ScalarMulAssign(ctGSW.Value[0].Value[0].Value, decomposed[0], e.buffer.ctProdLWE.Value)
	for j := 1; j < ctGSW.GadgetParameters.level; j++ {
		vec.ScalarMulAddAssign(ctGSW.Value[0].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
	}

	for i := 1; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulAddAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
		}
	}

	ctLWEOut.CopyFrom(e.buffer.ctProdLWE)
}

// ExternalProductAddLWEAssign computes the external product between ctGSW and ctLWE and adds it to ctLWEOut.
func (e *Evaluator[T]) ExternalProductAddLWEAssign(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T], ctLWEOut LWECiphertext[T]) {
	decomposed := e.Decomposer.ScalarDecomposedBuffer(ctGSW.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(ctLWE.Value[0], ctGSW.GadgetParameters, decomposed)
	vec.ScalarMulAssign(ctGSW.Value[0].Value[0].Value, decomposed[0], e.buffer.ctProdLWE.Value)
	for j := 1; j < ctGSW.GadgetParameters.level; j++ {
		vec.ScalarMulAddAssign(ctGSW.Value[0].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
	}

	for i := 1; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulAddAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
		}
	}

	e.AddLWEAssign(ctLWEOut, e.buffer.ctProdLWE, ctLWEOut)
}

// ExternalProductSubLWEAssign computes the external product between ctGSW and ctLWE and subtracts it from ctLWEOut.
func (e *Evaluator[T]) ExternalProductSubLWEAssign(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T], ctLWEOut LWECiphertext[T]) {
	decomposed := e.Decomposer.ScalarDecomposedBuffer(ctGSW.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(ctLWE.Value[0], ctGSW.GadgetParameters, decomposed)
	vec.ScalarMulAssign(ctGSW.Value[0].Value[0].Value, decomposed[0], e.buffer.ctProdLWE.Value)
	for j := 1; j < ctGSW.GadgetParameters.level; j++ {
		vec.ScalarMulAddAssign(ctGSW.Value[0].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
	}

	for i := 1; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulAddAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], e.buffer.ctProdLWE.Value)
		}
	}

	e.SubLWEAssign(ctLWEOut, e.buffer.ctProdLWE, ctLWEOut)
}

// ExternalProductGLWE returns the external product between ctFourierGGSW and ctGLWE.
func (e *Evaluator[T]) ExternalProductGLWE(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductGLWEAssign(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProductGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctProdFourierGLWE)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.Decomposer.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctProdFourierGLWE)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.Decomposer.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(ctFourierGGSW.GadgetParameters)

	e.Decomposer.DecomposePolyAssign(ctGLWE.Value[0], ctFourierGGSW.GadgetParameters, polyDecomposed)
	e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[0].Value[0], polyDecomposed[0], e.buffer.ctProdFourierGLWE)
	for j := 1; j < ctFourierGGSW.GadgetParameters.level; j++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[0].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
	}

	for i := 1; i < e.Parameters.glweRank+1; i++ {
		e.Decomposer.DecomposePolyAssign(ctGLWE.Value[i], ctFourierGGSW.GadgetParameters, polyDecomposed)
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], e.buffer.ctProdFourierGLWE)
		}
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolySubAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierDecomposedFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
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

// ExternalProductFourierDecomposedAddFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedAddFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductFourierDecomposedSubFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierDecomposedSubFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
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
	e.ExternalProductAddGLWEAssign(ctFourierGGSW, e.buffer.ctCMux, ctOut)
}
