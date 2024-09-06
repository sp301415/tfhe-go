package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GadgetProductLWE returns the gadget product between c and ctLev.
func (e *Evaluator[T]) GadgetProductLWE(ctLev LevCiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.GadgetProductAssignLWE(ctLev, c, ctOut)
	return ctOut
}

// GadgetProductAssignLWE computes the gadget product between c and ctLev and writes it to ctLWEOut.
func (e *Evaluator[T]) GadgetProductAssignLWE(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	decomposed := e.decomposedBuffer(ctLev.GadgetParameters)

	e.DecomposeAssign(c, ctLev.GadgetParameters, decomposed)
	vec.ScalarMulAssign(ctLev.Value[0].Value, decomposed[0], ctLWEOut.Value)
	for i := 1; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulAddAssign(ctLev.Value[i].Value, decomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductAddAssignLWE computes the gadget product between c and ctLev and adds it to ctLWEOut.
func (e *Evaluator[T]) GadgetProductAddAssignLWE(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	decomposed := e.decomposedBuffer(ctLev.GadgetParameters)

	e.DecomposeAssign(c, ctLev.GadgetParameters, decomposed)
	for i := 0; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulAddAssign(ctLev.Value[i].Value, decomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductSubAssignLWE computes the gadget product between c and ctLev and subtracts it from ctLWEOut.
func (e *Evaluator[T]) GadgetProductSubAssignLWE(ctLev LevCiphertext[T], c T, ctLWEOut LWECiphertext[T]) {
	decomposed := e.decomposedBuffer(ctLev.GadgetParameters)

	e.DecomposeAssign(c, ctLev.GadgetParameters, decomposed)
	for i := 0; i < ctLev.GadgetParameters.level; i++ {
		vec.ScalarMulSubAssign(ctLev.Value[i].Value, decomposed[i], ctLWEOut.Value)
	}
}

// GadgetProductGLWE returns the gadget product between p and ctFourierGLev.
func (e *Evaluator[T]) GadgetProductGLWE(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.GadgetProductAssignGLWE(ctFourierGLev, p, ctOut)
	return ctOut
}

// GadgetProductAssignGLWE computes the gadget product between p and ctFourierGLev and writes it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAssignGLWE(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductAddAssignGLWE computes the gadget product between p and ctFourierGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProductAddAssignGLWE(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductSubAssignGLWE computes the gadget product between p and ctFourierGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProductSubAssignGLWE(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctGLWEOut GLWECiphertext[T]) {
	polyDecomposed := e.polyDecomposedBuffer(ctFourierGLev.GadgetParameters)
	polyFourierDecomposed := e.polyFourierDecomposedBuffer(ctFourierGLev.GadgetParameters)

	e.DecomposePolyAssign(p, ctFourierGLev.GadgetParameters, polyDecomposed)
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], polyFourierDecomposed[i])
	}

	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyFourierDecomposed[0], e.buffer.ctFourierProd)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyFourierDecomposed[i], e.buffer.ctFourierProd)
	}

	for i := 0; i < e.Parameters.glweRank+1; i++ {
		e.PolyEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// GadgetProductHoistedFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductHoistedFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	e.FourierPolyMulFourierGLWEAssign(ctFourierGLev.Value[0], pDecomposed[0], ctFourierGLWEOut)
	for i := 1; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductHoistedAddFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductHoistedAddFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < ctFourierGLev.GadgetParameters.level; i++ {
		e.FourierPolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], pDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductHoistedSubFourierGLWEAssign computes the gadget product between fourier decomposed p and ctFourierGLev and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductHoistedSubFourierGLWEAssign(ctFourierGLev FourierGLevCiphertext[T], pDecomposed []poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
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
	decomposed := e.decomposedBuffer(ctGSW.GadgetParameters)

	e.DecomposeAssign(ctLWE.Value[0], ctGSW.GadgetParameters, decomposed)
	vec.ScalarMulAssign(ctGSW.Value[0].Value[0].Value, decomposed[0], ctLWEOut.Value)
	for j := 1; j < ctGSW.GadgetParameters.level; j++ {
		vec.ScalarMulAddAssign(ctGSW.Value[0].Value[j].Value, decomposed[j], ctLWEOut.Value)
	}

	for i := 1; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.DecomposeAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulAddAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], ctLWEOut.Value)
		}
	}
}

// ExternalProductAddLWEAssign computes the external product between ctGSW and ctLWE and adds it to ctLWEOut.
func (e *Evaluator[T]) ExternalProductAddLWEAssign(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T], ctLWEOut LWECiphertext[T]) {
	decomposed := e.decomposedBuffer(ctGSW.GadgetParameters)

	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.DecomposeAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulAddAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], ctLWEOut.Value)
		}
	}
}

// ExternalProductSubLWEAssign computes the external product between ctGSW and ctLWE and subtracts it from ctLWEOut.
func (e *Evaluator[T]) ExternalProductSubLWEAssign(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T], ctLWEOut LWECiphertext[T]) {
	decomposed := e.decomposedBuffer(ctGSW.GadgetParameters)

	for i := 0; i < e.Parameters.DefaultLWEDimension()+1; i++ {
		e.DecomposeAssign(ctLWE.Value[i], ctGSW.GadgetParameters, decomposed)
		for j := 0; j < ctGSW.GadgetParameters.level; j++ {
			vec.ScalarMulSubAssign(ctGSW.Value[i].Value[j].Value, decomposed[j], ctLWEOut.Value)
		}
	}
}

// ExternalProductGLWE returns the external product between ctFourierGGSW and ctGLWE.
func (e *Evaluator[T]) ExternalProductGLWE(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductGLWEAssign(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProductGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
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
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductAddGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
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
		e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubGLWEAssign computes the external product between ctFourierGGSW and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProductSubGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
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
		e.PolyEvaluator.ToPolySubAssignUnsafe(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductHoistedFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductHoistedFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
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

// ExternalProductHoistedAddFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and adds it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductHoistedAddFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank+1; i++ {
		for j := 0; j < ctFourierGGSW.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductHoistedSubFourierGLWEAssign computes the external product between ctFourierGGSW and fourier decomposed ctGLWE and subtracts it from ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductHoistedSubFourierGLWEAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctFourierGLWEOut FourierGLWECiphertext[T]) {
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
