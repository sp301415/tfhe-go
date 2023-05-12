package tfhe

import (
	"github.com/sp301415/tfhe/math/poly"
)

// Decompose decomposes x with respect to decompParams.
// Equivalent to decompParams.Decompose().
func (e Evaluater[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	return decompParams.Decompose(x)
}

// DecomposeInplace decomposes x with respect to decompParams.
// Equivalent to decompParams.DecomposeInPlace().
func (e Evaluater[T]) DecomposeInPlace(x T, d []T, decompParams DecompositionParameters[T]) {
	decompParams.DecomposeInPlace(x, d)
}

// DecomposePoly decomposes x with respect to decompParams.
// Equivalant to decompParams.DecomposePoly().
func (e Evaluater[T]) DecomposePoly(x poly.Poly[T], decompParams DecompositionParameters[T]) []poly.Poly[T] {
	return decompParams.DecomposePoly(x)
}

// DecomposePolyInPlace decomposes x with respect to decompParams.
// Equivalant to decompParams.DecomposePolyInPlace().
func (e Evaluater[T]) DecomposePolyInplace(x poly.Poly[T], d []poly.Poly[T], decompParams DecompositionParameters[T]) {
	decompParams.DecomposePolyInPlace(x, d)
}

// ToStandardGGSWInPlace transforms FourierGGSW ciphertext to GGSW ciphertext.
func (e Evaluater[T]) ToStandardGGSWInPlace(ctIn FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctIn.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierTransformer.ToScaledStandardPolyInPlace(ctIn.Value[i].Value[j].Value[k], ctOut.Value[i].Value[j].Value[k])

			}
		}
	}
}

// ToFourierGGSWInPlace transforms GGSW ciphertext to FourierGGSW ciphertext.
func (e Evaluater[T]) ToFourierGGSWInPlace(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctIn.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierTransformer.ToScaledFourierPolyInPlace(ctIn.Value[i].Value[j].Value[k], ctOut.Value[i].Value[j].Value[k])

			}
		}
	}
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
	buffDecomposed := make([]poly.Poly[T], ctGGSW.decompParams.level)
	for i := 0; i < ctGGSW.decompParams.level; i++ {
		buffDecomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				if i == 0 && j == 0 {
					e.PolyEvaluater.MulInPlace(ctGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], ctGLWEOut.Value[k])
				} else {
					e.PolyEvaluater.MulAddAssign(ctGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], ctGLWEOut.Value[k])
				}
			}
		}
	}
}

// ExternalProductFourierInPlace calculates the external product between
// ctFourierGGSW and ctGLWE, and returns it.
func (e Evaluater[T]) ExternalProductFourier(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ExternalProductFourierInPlace(ctFourierGGSW, ctGLWE, ctOut)
	return ctOut
}

// ExternalProductFourierInPlace calculates the external product between
// ctFourierGGSW and ctGLWE, and writes it to ctOut.
func (e Evaluater[T]) ExternalProductFourierInPlace(ctFourierGGSW FourierGGSWCiphertext[T], ctGLWE, ctGLWEOut GLWECiphertext[T]) {
	buffDecomposed := make([]poly.Poly[T], ctFourierGGSW.decompParams.level)
	for i := 0; i < ctFourierGGSW.decompParams.level; i++ {
		buffDecomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				if i == 0 && j == 0 {
					e.FourierTransformer.MulWithStandardInPlace(ctFourierGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], e.buffer.glweFourierCtOutForExtProd.Value[k])
				} else {
					e.FourierTransformer.MulWithStandardAddAssign(ctFourierGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], e.buffer.glweFourierCtOutForExtProd.Value[k])
				}
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(e.buffer.glweFourierCtOutForExtProd.Value[i], ctGLWEOut.Value[i])
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
	e.SubGLWEInPlace(ct1, ct0, e.buffer.glweCtForCMux)              // buff = ct1 - ct0
	e.ExternalProductInPlace(ctGGSW, e.buffer.glweCtForCMux, ctOut) // ctOut = ctGGSW * (ct1 - ct0)
	e.AddGLWEAssign(ct0, ctOut)                                     // ctOut = ct0 + ctGGSW * (ct1 - ct0)
}

// CMuxFourier calculates the CMUX between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if caluse; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxFourier(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1 GLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.CMuxFourierInPlace(ctFourierGGSW, ct0, ct1, ctOut)
	return ctOut
}

// CMuxFourierInPlace calculates the CMUX between ctFourierGGSW, ct0 and ct1: so ctOut = ct0 + ctGGSW * (ct1 - ct0).
// CMUX essentially acts as an if caluse; if ctGGSW = 0, ct0 is returned, and if ctGGSW = 1, ct1 is returned.
func (e Evaluater[T]) CMuxFourierInPlace(ctFourierGGSW FourierGGSWCiphertext[T], ct0, ct1, ctOut GLWECiphertext[T]) {
	e.SubGLWEInPlace(ct1, ct0, e.buffer.glweCtForCMux)                            // buff = ct1 - ct0
	e.ExternalProductFourierInPlace(ctFourierGGSW, e.buffer.glweCtForCMux, ctOut) // ctOut = ctGGSW * (ct1 - ct0)
	e.AddGLWEAssign(ct0, ctOut)                                                   // ctOut = ct0 + ctGGSW * (ct1 - ct0)
}
