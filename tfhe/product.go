package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
)

// Decompose decomposes x with respect to decompParams.
// Equivalent to decompParams.Decompose().
func (e Evaluater[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	decomposed := make([]T, decompParams.level)
	e.DecomposeInPlace(x, decomposed, decompParams)
	return decomposed
}

// DecomposeInplace decomposes x with respect to decompParams.
// Equivalent to decompParams.DecomposeInPlace().
func (e Evaluater[T]) DecomposeInPlace(x T, d []T, decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	u := num.ClosestMultipleBits(x, lastScaledBaseLog) >> lastScaledBaseLog
	for i := decompParams.level - 1; i >= 1; i-- {
		d[i] = u & (decompParams.base - 1)
		u >>= decompParams.baseLog
		u += d[i] >> (decompParams.baseLog - 1)
		d[i] -= (d[i] & decompParams.baseHalf) << 1
	}
	d[0] = u & (decompParams.base - 1)
	d[0] -= (d[0] & decompParams.baseHalf) << 1
}

// DecomposePoly decomposes x with respect to decompParams.
// Equivalant to decompParams.DecomposePoly().
func (e Evaluater[T]) DecomposePoly(x poly.Poly[T], decompParams DecompositionParameters[T]) []poly.Poly[T] {
	decomposed := make([]poly.Poly[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		decomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}
	e.DecomposePolyInplace(x, decomposed, decompParams)
	return decomposed
}

// DecomposePolyInPlace decomposes x with respect to decompParams.
// Equivalant to decompParams.DecomposePolyInPlace().
func (e Evaluater[T]) DecomposePolyInplace(x poly.Poly[T], d []poly.Poly[T], decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	for i := 0; i < e.Parameters.polyDegree; i++ {
		c := num.ClosestMultipleBits(x.Coeffs[i], lastScaledBaseLog) >> lastScaledBaseLog
		for j := decompParams.level - 1; j >= 1; j-- {
			d[j].Coeffs[i] = c & (decompParams.base - 1)
			c >>= decompParams.baseLog
			c += d[j].Coeffs[i] >> (decompParams.baseLog - 1)
			d[j].Coeffs[i] -= (d[j].Coeffs[i] & decompParams.baseHalf) << 1
		}
		d[0].Coeffs[i] = c & (decompParams.base - 1)
		d[0].Coeffs[i] -= (d[0].Coeffs[i] & decompParams.baseHalf) << 1
	}
}

// decomposedPolyBuffer returns the decomposedPoly buffer of Evaluater.
// if len(decomposedPoly) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluater and returns it.
func (e *Evaluater[T]) decomposedPolyBuffer(decompParams DecompositionParameters[T]) []poly.Poly[T] {
	if len(e.buffer.decomposedPoly) >= decompParams.level {
		return e.buffer.decomposedPoly[:decompParams.level]
	}

	oldLen := len(e.buffer.decomposedPoly)
	e.buffer.decomposedPoly = append(e.buffer.decomposedPoly, make([]poly.Poly[T], decompParams.level-oldLen)...)
	for i := oldLen; i < decompParams.level; i++ {
		e.buffer.decomposedPoly[i] = poly.New[T](e.Parameters.polyDegree)
	}

	return e.buffer.decomposedPoly
}

// decomposedVecBuffer returns the decomposedVec buffer of Evaluater.
// if len(decomposedVec) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluater and returns it.
func (e *Evaluater[T]) decomposedVecBuffer(decompParams DecompositionParameters[T]) []T {
	if len(e.buffer.decomposedVec) >= decompParams.level {
		return e.buffer.decomposedVec[:decompParams.level]
	}

	oldLen := len(e.buffer.decomposedVec)
	e.buffer.decomposedVec = append(e.buffer.decomposedVec, make([]T, decompParams.level-oldLen)...)
	return e.buffer.decomposedVec
}

// ExternalProduct calculates the external product between
// ctGGSW and ctGLWE, and returns the result GLWE ciphertext.
func (e Evaluater[T]) ExternalProduct(ctGGSW GGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductInPlace(ctGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductInPlace calculates the external product between
// ctGGSW and ctGLWE, and writes it to ctOut.
func (e Evaluater[T]) ExternalProductInPlace(ctGGSW GGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulGLWEInPlace(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWEOut)
			} else {
				e.PolyMulAddGLWEAssign(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWEOut)
			}
		}
	}
}

// ExternalProductAssign calculates the external product between
// ctGGSW and ctGLWE, and writes it to ctGLWE.
func (e Evaluater[T]) ExternalProductAssign(ctGGSW GGSWCiphertext[T], ctGLWE GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulGLWEInPlace(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWE)
			} else {
				e.PolyMulAddGLWEAssign(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWE)
			}
		}
	}
}

// ExternalProductAddAssign calculates the external product between
// ctGGSW and ctGLWE, and adds it to ctGLWEOut.
func (e Evaluater[T]) ExternalProductAddAssign(ctGGSW GGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			e.PolyMulAddGLWEAssign(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWEOut)
		}
	}
}

// ExternalProductSubAssign calculates the external product between
// ctGGSW and ctGLWE, and subtracts it from ctGLWEOut.
func (e Evaluater[T]) ExternalProductSubAssign(ctGGSW GGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			e.PolyMulSubGLWEAssign(ctGGSW.Value[i].Value[j], buffDecomposed[j], ctGLWEOut)
		}
	}
}

// ExternalProductFourier calculates the external product between
// ctFourierGGSW and ctGLWE, and returns it.
func (e Evaluater[T]) ExternalProductFourier(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductFourierInPlace(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductFourierInPlace calculates the external product between
// ctFourierGGSW and ctGLWE, and writes it to ctGLWEOut.
func (e Evaluater[T]) ExternalProductFourierInPlace(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEInPlace(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			} else {
				e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(e.buffer.fourierCtOutForExtProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and writes it to ctGLWE.
func (e Evaluater[T]) ExternalProductFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEInPlace(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			} else {
				e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(e.buffer.fourierCtOutForExtProd.Value[i], ctGLWE.Value[i])
	}
}

// ExternalProductFourierAddAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and adds it to ctOut.
func (e Evaluater[T]) ExternalProductFourierAddAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEInPlace(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			} else {
				e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyAddAssign(e.buffer.fourierCtOutForExtProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierSubAssign calculates the external product between
// ctFourierGGSW and ctGLWE, and subtracts it from ctOut.
func (e Evaluater[T]) ExternalProductFourierSubAssign(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := e.decomposedPolyBuffer(ctFourierGGSW.decompParams)

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.PolyMulFourierGLWEInPlace(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			} else {
				e.PolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], buffDecomposed[j], e.buffer.fourierCtOutForExtProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolySubAssign(e.buffer.fourierCtOutForExtProd.Value[i], ctGLWEOut.Value[i])
	}
}

// ExternalProductFourierHoisted calculates the external product between
// ctFourierGGSW and decomposed ctGLWE, and returns it.
func (e Evaluater[T]) ExternalProductFourierHoisted(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE [][]poly.FourierPoly) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductFourierHoistedInPlace(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductFourierHoistedInPlace calculates the external product between
// ctFourierGGSW and decomposed ctGLWE, and writes it to ctGLWEOut.
func (e Evaluater[T]) ExternalProductFourierHoistedInPlace(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE [][]poly.FourierPoly, ctGLWEOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			if i == 0 && j == 0 {
				e.FourierPolyMulFourierGLWEInPlace(ctFourierGGSW.Value[i].Value[j], ctGLWE[i][j], e.buffer.fourierCtOutForExtProd)
			} else {
				e.FourierPolyMulAddFourierGLWEAssign(ctFourierGGSW.Value[i].Value[j], ctGLWE[i][j], e.buffer.fourierCtOutForExtProd)
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(e.buffer.fourierCtOutForExtProd.Value[i], ctGLWEOut.Value[i])
	}
}

// CMux calculates the CMUX between ctGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if caluse; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMux(ctGGSW GGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.CMuxInPlace(ctGGSW, ct0, ct1, ctOut)
	return ctOut
}

// CMuxInPlace calculates the CMUX between ctGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if caluse; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxInPlace(ctGGSW GGSWCiphertext[T], ct0, ct1, ctOut GLWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	e.SubGLWEInPlace(ct1, ct0, e.buffer.ctSubForCMux)
	e.ExternalProductAddAssign(ctGGSW, e.buffer.ctSubForCMux, ctOut)
}

// CMuxFourier calculates the CMUX between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if clause; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxFourier(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.CMuxFourierInPlace(ctFourierGGSW, ct0, ct1, ctOut)
	return ctOut
}

// CMuxFourierInPlace calculates the CMUX between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if clause; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxFourierInPlace(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1, ctOut GLWECiphertext[T]) {
	ctOut.CopyFrom(ct0)
	e.SubGLWEInPlace(ct1, ct0, e.buffer.ctSubForCMux)
	e.ExternalProductFourierAddAssign(ctFourierGGSW, e.buffer.ctSubForCMux, ctOut)
}

// CMuxFourierAssign calculates the CMUX between ctFourierGGSW, ct0 and ct1 and writes it to ct0: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if clause; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxFourierAssign(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) {
	e.SubGLWEInPlace(ct1, ct0, e.buffer.ctSubForCMux)
	e.ExternalProductFourierAddAssign(ctFourierGGSW, e.buffer.ctSubForCMux, ct0)
}
