package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
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
	e.GadgetProductFourierAssign(ctFourierGLev, p, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAssign(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductAddAssign calculates the gadget product between
// ctFourierGLev and p, and adds it to ctOut.
func (e *Evaluator[T]) GadgetProductAddAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	e.GadgetProductFourierAssign(ctFourierGLev, p, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAddAssign(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductSubAssign calculates the gadget product between
// ctFourierGLev and p, and subtracts it from ctOut.
func (e *Evaluator[T]) GadgetProductSubAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctOut GLWECiphertext[T]) {
	e.GadgetProductFourierAssign(ctFourierGLev, p, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolySubAssign(e.buffer.ctFourierProd.Value[i], ctOut.Value[i])
	}
}

// GadgetProductFourier calculates the gadget product between
// ctFourierGLev and p, and returns it in Fourier form.
func (e *Evaluator[T]) GadgetProductFourier(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.GadgetProductFourierAssign(ctFourierGLev, p, ctOut)
	return ctOut
}

// GadgetProductFourierAssign calculates the gadget product between
// ctFourierGLev and p, and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) GadgetProductFourierAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGLev.decompParams)

	e.DecomposePolyAssign(p, polyDecomposed, ctFourierGLev.decompParams)
	e.PolyMulFourierGLWEAssign(ctFourierGLev.Value[0], polyDecomposed[0], ctFourierGLWEOut)
	for i := 1; i < ctFourierGLev.decompParams.level; i++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierAddAssign calculates the gadget product between
// ctFourierGLev and p, and adds it to ctOut.
func (e *Evaluator[T]) GadgetProductFourierAddAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGLev.decompParams)

	for i := 0; i < ctFourierGLev.decompParams.level; i++ {
		e.PolyMulAddFourierGLWEAssign(ctFourierGLev.Value[i], polyDecomposed[i], ctFourierGLWEOut)
	}
}

// GadgetProductFourierSubAssign calculates the gadget product between
// ctFourierGLev and p, and subtracts it from ctOut.
func (e *Evaluator[T]) GadgetProductFourierSubAssign(ctFourierGLev FourierGLevCiphertext[T], p poly.Poly[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGLev.decompParams)

	for i := 0; i < ctFourierGLev.decompParams.level; i++ {
		e.PolyMulSubFourierGLWEAssign(ctFourierGLev.Value[i], polyDecomposed[i], ctFourierGLWEOut)
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
	e.ExternalProductFourierAssign(ctFourierGGSW, ctGLWE, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAssign(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductAddAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and adds it to ctOut.
func (e *Evaluator[T]) ExternalProductAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	e.ExternalProductFourierAssign(ctFourierGGSW, ctGLWE, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAddAssign(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductSubAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and subtracts it from ctOut.
func (e *Evaluator[T]) ExternalProductSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	e.ExternalProductFourierAssign(ctFourierGGSW, ctGLWE, e.buffer.ctFourierProd)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolySubAssign(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourier calculates the external product between
// ctFourierGGSW and ctFourierGLWE, and returns it in Fourier form.
func (e *Evaluator[T]) ExternalProductFourier(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.ExternalProductFourierAssign(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductFourierAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and writes it to ctFourierGLWEOut.
func (e *Evaluator[T]) ExternalProductFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], polyDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], ctFourierGLWEOut)
			} else {
				e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], ctFourierGLWEOut)
			}
		}
	}
}

// ExternalProductFourierAddAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and adds it to ctOut.
func (e *Evaluator[T]) ExternalProductFourierAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], polyDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductFourierSubAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and subtracts it from ctOut.
func (e *Evaluator[T]) ExternalProductFourierSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T], ctFourierGLWEOut FourierGLWECiphertext[T]) {
	polyDecomposed := e.getPolyDecomposedBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyAssign(ctGLWE.Value[i], polyDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			e.PolyMulSubFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], polyDecomposed[j], ctFourierGLWEOut)
		}
	}
}

// ExternalProductHoisted calculates the external product between
// ctFourierGGSW and decomposed ctGLWE, and returns it.
func (e *Evaluator[T]) ExternalProductHoisted(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductHoistedAssign(ctFourierGGSW, ctGLWEDecomposed, ctOut)
	return ctOut
}

// ExternalProductHoistedAssign calculates the external product between
// ctFourierGGSW and decomposed ctGLWE, and writes it to ctGLWEOut.
func (e *Evaluator[T]) ExternalProductHoistedAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWEDecomposed [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.FourierPolyMulFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], e.buffer.ctFourierProd)
			} else {
				e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWEDecomposed[i][j], e.buffer.ctFourierProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAssign(e.buffer.ctFourierProd.Value[i], ctGLWEOut.Value[i])
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
