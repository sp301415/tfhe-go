package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// GadgetProdLWE returns the gadget product between c and ctLev.
func (e *Evaluator[T]) GadgetProdLWE(ctLev LevCiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.GadgetProdLWETo(ctOut, ctLev, c)
	return ctOut
}

// GadgetProdLWETo computes the gadget product between c and ctLev and writes it to ctLWEOut.
func (e *Evaluator[T]) GadgetProdLWETo(ctLWEOut LWECiphertext[T], ctLev LevCiphertext[T], c T) {
	cDcmp := e.Decomposer.ScalarBuffer(ctLev.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, c, ctLev.GadgetParams)
	vec.ScalarMulTo(ctLWEOut.Value, ctLev.Value[0].Value, cDcmp[0])
	for i := 1; i < ctLev.GadgetParams.level; i++ {
		vec.ScalarMulAddTo(ctLWEOut.Value, ctLev.Value[i].Value, cDcmp[i])
	}
}

// GadgetProdAddLWETo computes the gadget product between c and ctLev and adds it to ctLWEOut.
func (e *Evaluator[T]) GadgetProdAddLWETo(ctLWEOut LWECiphertext[T], ctLev LevCiphertext[T], c T) {
	cDcmp := e.Decomposer.ScalarBuffer(ctLev.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, c, ctLev.GadgetParams)
	for i := 0; i < ctLev.GadgetParams.level; i++ {
		vec.ScalarMulAddTo(ctLWEOut.Value, ctLev.Value[i].Value, cDcmp[i])
	}
}

// GadgetProdSubLWETo computes the gadget product between c and ctLev and subtracts it from ctLWEOut.
func (e *Evaluator[T]) GadgetProdSubLWETo(ctLWEOut LWECiphertext[T], ctLev LevCiphertext[T], c T) {
	cDcmp := e.Decomposer.ScalarBuffer(ctLev.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, c, ctLev.GadgetParams)
	for i := 0; i < ctLev.GadgetParams.level; i++ {
		vec.ScalarMulSubTo(ctLWEOut.Value, ctLev.Value[i].Value, cDcmp[i])
	}
}

// GadgetProdGLWE returns the gadget product between p and ctFFTGLev.
func (e *Evaluator[T]) GadgetProdGLWE(ctFFTGLev FFTGLevCiphertext[T], p poly.Poly[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.GadgetProdGLWETo(ctOut, ctFFTGLev, p)
	return ctOut
}

// GadgetProdGLWETo computes the gadget product between p and ctFFTGLev and writes it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProdGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], p poly.Poly[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGLev.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTGLev.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, p, ctFFTGLev.GadgetParams)
	for i := 0; i < ctFFTGLev.GadgetParams.level; i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	e.FFTPolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[0], fpDcmp[0])
	for i := 1; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[i], fpDcmp[i])
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// GadgetProdAddGLWETo computes the gadget product between p and ctFFTGLev and adds it to ctGLWEOut.
func (e *Evaluator[T]) GadgetProdAddGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], p poly.Poly[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGLev.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTGLev.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, p, ctFFTGLev.GadgetParams)
	for i := 0; i < ctFFTGLev.GadgetParams.level; i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	e.FFTPolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[0], fpDcmp[0])
	for i := 1; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[i], fpDcmp[i])
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// GadgetProdSubGLWETo computes the gadget product between p and ctFFTGLev and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) GadgetProdSubGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], p poly.Poly[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGLev.GadgetParams)
	fpDcmp := e.Decomposer.FFTPolyBuffer(ctFFTGLev.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, p, ctFFTGLev.GadgetParams)
	for i := 0; i < ctFFTGLev.GadgetParams.level; i++ {
		e.PolyEvaluator.FFTTo(fpDcmp[i], pDcmp[i])
	}

	e.FFTPolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[0], fpDcmp[0])
	for i := 1; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGLev.Value[i], fpDcmp[i])
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTSubToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// GadgetProdFFTGLWETo computes the gadget product between fourier decomposed p and ctFFTGLev and writes it to ctFFTGLWEOut.
func (e *Evaluator[T]) GadgetProdFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], pDcmp []poly.FFTPoly) {
	e.FFTPolyMulFFTGLWETo(ctFFTGLWEOut, ctFFTGLev.Value[0], pDcmp[0])
	for i := 1; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulAddFFTGLWETo(ctFFTGLWEOut, ctFFTGLev.Value[i], pDcmp[i])
	}
}

// GadgetProdAddFFTGLWETo computes the gadget product between fourier decomposed p and ctFFTGLev and adds it to ctFFTGLWEOut.
func (e *Evaluator[T]) GadgetProdAddFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], pDcmp []poly.FFTPoly) {
	for i := 0; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulAddFFTGLWETo(ctFFTGLWEOut, ctFFTGLev.Value[i], pDcmp[i])
	}
}

// GadgetProdSubFFTGLWETo computes the gadget product between fourier decomposed p and ctFFTGLev and subtracts it from ctFFTGLWEOut.
func (e *Evaluator[T]) GadgetProdSubFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGLev FFTGLevCiphertext[T], pDcmp []poly.FFTPoly) {
	for i := 0; i < ctFFTGLev.GadgetParams.level; i++ {
		e.FFTPolyMulSubFFTGLWETo(ctFFTGLWEOut, ctFFTGLev.Value[i], pDcmp[i])
	}
}

// ExternalProdLWE returns the external product between ctGSW and ctLWE.
func (e *Evaluator[T]) ExternalProdLWE(ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.ExternalProdLWETo(ctOut, ctGSW, ctLWE)
	return ctOut
}

// ExternalProdLWETo computes the external product between ctGSW and ctLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProdLWETo(ctLWEOut LWECiphertext[T], ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T]) {
	cDcmp := e.Decomposer.ScalarBuffer(ctGSW.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[0], ctGSW.GadgetParams)
	vec.ScalarMulTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[0].Value, cDcmp[0])
	for j := 1; j < ctGSW.GadgetParams.level; j++ {
		vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[j].Value, cDcmp[j])
	}

	for i := 1; i < e.Params.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[i], ctGSW.GadgetParams)
		for j := 0; j < ctGSW.GadgetParams.level; j++ {
			vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[i].Value[j].Value, cDcmp[j])
		}
	}

	ctLWEOut.CopyFrom(e.buf.ctProdLWE)
}

// ExternalProdAddLWETo computes the external product between ctGSW and ctLWE and adds it to ctLWEOut.
func (e *Evaluator[T]) ExternalProdAddLWETo(ctLWEOut LWECiphertext[T], ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T]) {
	cDcmp := e.Decomposer.ScalarBuffer(ctGSW.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[0], ctGSW.GadgetParams)
	vec.ScalarMulTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[0].Value, cDcmp[0])
	for j := 1; j < ctGSW.GadgetParams.level; j++ {
		vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[j].Value, cDcmp[j])
	}

	for i := 1; i < e.Params.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[i], ctGSW.GadgetParams)
		for j := 0; j < ctGSW.GadgetParams.level; j++ {
			vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[i].Value[j].Value, cDcmp[j])
		}
	}

	e.AddLWETo(ctLWEOut, ctLWEOut, e.buf.ctProdLWE)
}

// ExternalProdSubLWETo computes the external product between ctGSW and ctLWE and subtracts it from ctLWEOut.
func (e *Evaluator[T]) ExternalProdSubLWETo(ctLWEOut LWECiphertext[T], ctGSW GSWCiphertext[T], ctLWE LWECiphertext[T]) {
	cDcmp := e.Decomposer.ScalarBuffer(ctGSW.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[0], ctGSW.GadgetParams)
	vec.ScalarMulTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[0].Value, cDcmp[0])
	for j := 1; j < ctGSW.GadgetParams.level; j++ {
		vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[0].Value[j].Value, cDcmp[j])
	}

	for i := 1; i < e.Params.DefaultLWEDimension()+1; i++ {
		e.Decomposer.DecomposeScalarTo(cDcmp, ctLWE.Value[i], ctGSW.GadgetParams)
		for j := 0; j < ctGSW.GadgetParams.level; j++ {
			vec.ScalarMulAddTo(e.buf.ctProdLWE.Value, ctGSW.Value[i].Value[j].Value, cDcmp[j])
		}
	}

	e.SubLWETo(ctLWEOut, ctLWEOut, e.buf.ctProdLWE)
}

// ExternalProdGLWE returns the external product between ctFFTGGSW and ctGLWE.
func (e *Evaluator[T]) ExternalProdGLWE(ctFFTGGSW FFTGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.ExternalProdGLWETo(ctOut, ctFFTGGSW, ctGLWE)
	return ctOut
}

// ExternalProdGLWETo computes the external product between ctFFTGGSW and ctGLWE and writes it to ctOut.
func (e *Evaluator[T]) ExternalProdGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGGSW.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTGGSW.GadgetParams)
	e.PolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[0], pDcmp[0])
	for j := 1; j < ctFFTGGSW.GadgetParams.level; j++ {
		e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[j], pDcmp[j])
	}

	for i := 1; i < e.Params.glweRank+1; i++ {
		e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i], ctFFTGGSW.GadgetParams)
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[i].Value[j], pDcmp[j])
		}
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// ExternalProdAddGLWETo computes the external product between ctFFTGGSW and ctGLWE and adds it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProdAddGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGGSW.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTGGSW.GadgetParams)
	e.PolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[0], pDcmp[0])
	for j := 1; j < ctFFTGGSW.GadgetParams.level; j++ {
		e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[j], pDcmp[j])
	}

	for i := 1; i < e.Params.glweRank+1; i++ {
		e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i], ctFFTGGSW.GadgetParams)
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[i].Value[j], pDcmp[j])
		}
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTAddToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// ExternalProdSubGLWETo computes the external product between ctFFTGGSW and ctGLWE and subtracts it from ctGLWEOut.
func (e *Evaluator[T]) ExternalProdSubGLWETo(ctGLWEOut GLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) {
	pDcmp := e.Decomposer.PolyBuffer(ctFFTGGSW.GadgetParams)

	e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[0], ctFFTGGSW.GadgetParams)
	e.PolyMulFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[0], pDcmp[0])
	for j := 1; j < ctFFTGGSW.GadgetParams.level; j++ {
		e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[0].Value[j], pDcmp[j])
	}

	for i := 1; i < e.Params.glweRank+1; i++ {
		e.Decomposer.DecomposePolyTo(pDcmp, ctGLWE.Value[i], ctFFTGGSW.GadgetParams)
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.PolyMulAddFFTGLWETo(e.buf.fctProdGLWE, ctFFTGGSW.Value[i].Value[j], pDcmp[j])
		}
	}

	for i := 0; i < e.Params.glweRank+1; i++ {
		e.PolyEvaluator.InvFFTSubToUnsafe(ctGLWEOut.Value[i], e.buf.fctProdGLWE.Value[i])
	}
}

// ExternalProdFFTGLWETo computes the external product between ctFFTGGSW and fourier decomposed ctGLWE and writes it to ctFFTGLWEOut.
func (e *Evaluator[T]) ExternalProdFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWEDcmp [][]poly.FFTPoly) {
	e.FFTPolyMulFFTGLWETo(ctFFTGLWEOut, ctFFTGGSW.Value[0].Value[0], ctGLWEDcmp[0][0])
	for j := 1; j < ctFFTGGSW.GadgetParams.level; j++ {
		e.FFTPolyMulAddFFTGLWETo(ctFFTGLWEOut, ctFFTGGSW.Value[0].Value[j], ctGLWEDcmp[0][j])
	}

	for i := 1; i < e.Params.glweRank+1; i++ {
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.FFTPolyMulAddFFTGLWETo(ctFFTGLWEOut, ctFFTGGSW.Value[i].Value[j], ctGLWEDcmp[i][j])
		}
	}
}

// ExternalProdAddFFTGLWETo computes the external product between ctFFTGGSW and fourier decomposed ctGLWE and adds it to ctFFTGLWEOut.
func (e *Evaluator[T]) ExternalProdAddFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWEDcmp [][]poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.FFTPolyMulAddFFTGLWETo(ctFFTGLWEOut, ctFFTGGSW.Value[i].Value[j], ctGLWEDcmp[i][j])
		}
	}
}

// ExternalProdSubFFTGLWETo computes the external product between ctFFTGGSW and fourier decomposed ctGLWE and subtracts it from ctFFTGLWEOut.
func (e *Evaluator[T]) ExternalProdSubFFTGLWETo(ctFFTGLWEOut FFTGLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ctGLWEDcmp [][]poly.FFTPoly) {
	for i := 0; i < e.Params.glweRank+1; i++ {
		for j := 0; j < ctFFTGGSW.GadgetParams.level; j++ {
			e.FFTPolyMulSubFFTGLWETo(ctFFTGLWEOut, ctFFTGGSW.Value[i].Value[j], ctGLWEDcmp[i][j])
		}
	}
}

// CMux returns the mux gate between ctFFTGGSW, ct0 and ct1: so ctOut = ct0 + ctFFTGGSW * (ct1 - ct0).
// CMux essentially acts as an if clause; if ctFFTGGSW = 0, ct0 is returned, and if ctFFTGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMux(ctFFTGGSW FFTGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.CMuxTo(ctOut, ctFFTGGSW, ct0, ct1)
	return ctOut
}

// CMuxTo computes the mux gate between ctFFTGGSW, ct0 and ct1: so ctOut = ct0 + ctFFTGGSW * (ct1 - ct0) and writes it to ctOut.
// CMux essentially acts as an if clause; if ctFFTGGSW = 0, ct0 is returned, and if ctFFTGGSW = 1, ct1 is returned.
func (e *Evaluator[T]) CMuxTo(ctOut GLWECiphertext[T], ctFFTGGSW FFTGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	e.SubGLWETo(e.buf.ctCMux, ct1, ct0)
	e.ExternalProdAddGLWETo(ctOut, ctFFTGGSW, e.buf.ctCMux)
}
