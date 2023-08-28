package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
)

// Decompose decomposes x with respect to decompParams.
func (e *Evaluator[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	decomposed := make([]T, decompParams.level)
	e.DecomposeAssign(x, decomposed, decompParams)
	return decomposed
}

// DecomposeAssign decomposes x with respect to decompParams, and writes it to d.
func (e *Evaluator[T]) DecomposeAssign(x T, d []T, decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	u := num.ClosestMultipleBits(x, lastScaledBaseLog) >> lastScaledBaseLog
	for i := decompParams.level - 1; i >= 1; i-- {
		d[i] = u & decompParams.baseMask
		u >>= decompParams.baseLog
		u += d[i] >> (decompParams.baseLog - 1)
		d[i] -= (d[i] & decompParams.baseHalf) << 1
	}
	d[0] = u & decompParams.baseMask
	d[0] -= (d[0] & decompParams.baseHalf) << 1
}

// DecomposePoly decomposes x with respect to decompParams.
func (e *Evaluator[T]) DecomposePoly(x poly.Poly[T], decompParams DecompositionParameters[T]) []poly.Poly[T] {
	decomposed := make([]poly.Poly[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		decomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}
	e.DecomposePolyAssign(x, decomposed, decompParams)
	return decomposed
}

// DecomposePolyAssign decomposes x with respect to decompParams, and writes it to d.
func (e *Evaluator[T]) DecomposePolyAssign(x poly.Poly[T], d []poly.Poly[T], decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	for i := 0; i < e.Parameters.polyDegree; i++ {
		c := num.ClosestMultipleBits(x.Coeffs[i], lastScaledBaseLog) >> lastScaledBaseLog
		for j := decompParams.level - 1; j >= 1; j-- {
			d[j].Coeffs[i] = c & decompParams.baseMask
			c >>= decompParams.baseLog
			c += d[j].Coeffs[i] >> (decompParams.baseLog - 1)
			d[j].Coeffs[i] -= (d[j].Coeffs[i] & decompParams.baseHalf) << 1
		}
		d[0].Coeffs[i] = c & decompParams.baseMask
		d[0].Coeffs[i] -= (d[0].Coeffs[i] & decompParams.baseHalf) << 1
	}
}

// getPolyDecomposedBuffer returns the polyDecomposed buffer of Evaluator.
// if len(polyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) getPolyDecomposedBuffer(decompParams DecompositionParameters[T]) []poly.Poly[T] {
	if len(e.buffer.polyDecomposed) >= decompParams.level {
		return e.buffer.polyDecomposed[:decompParams.level]
	}

	oldLen := len(e.buffer.polyDecomposed)
	e.buffer.polyDecomposed = append(e.buffer.polyDecomposed, make([]poly.Poly[T], decompParams.level-oldLen)...)
	for i := oldLen; i < decompParams.level; i++ {
		e.buffer.polyDecomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}
	return e.buffer.polyDecomposed
}

// getVecDecomposedBuffer returns the vecDecomposed buffer of Evaluator.
// if len(vecDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) getVecDecomposedBuffer(decompParams DecompositionParameters[T]) []T {
	if len(e.buffer.vecDecomposed) >= decompParams.level {
		return e.buffer.vecDecomposed[:decompParams.level]
	}

	oldLen := len(e.buffer.vecDecomposed)
	e.buffer.vecDecomposed = append(e.buffer.vecDecomposed, make([]T, decompParams.level-oldLen)...)
	return e.buffer.vecDecomposed
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
