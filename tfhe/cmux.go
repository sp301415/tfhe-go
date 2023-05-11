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
				e.FourierTransformer.ToStandardPolyInPlace(ctIn.Value[i].Value[j].Value[k], ctOut.Value[i].Value[j].Value[k])

			}
		}
	}
}

// ToFourierGGSWInPlace transforms GGSW ciphertext to FourierGGSW ciphertext.
func (e Evaluater[T]) ToFourierGGSWInPlace(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < ctIn.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierTransformer.ToFourierPolyInPlace(ctIn.Value[i].Value[j].Value[k], ctOut.Value[i].Value[j].Value[k])

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
		ctGLWEOut.Value[i].Clear()
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctGGSW.decompParams)
		for j := 0; j < ctGGSW.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.PolyEvaluater.MulAddAssign(ctGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], ctGLWEOut.Value[k])
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
		e.buffer.fourierGLWEOut.Value[i].Clear()
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.DecomposePolyInplace(ctGLWE.Value[i], buffDecomposed, ctFourierGGSW.decompParams)
		for j := 0; j < ctFourierGGSW.decompParams.level; j++ {
			for k := 0; k < e.Parameters.glweDimension+1; k++ {
				e.FourierTransformer.MulWithStandardAddAssign(ctFourierGGSW.Value[i].Value[j].Value[k], buffDecomposed[j], e.buffer.fourierGLWEOut.Value[k])
			}
		}
	}

	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(e.buffer.fourierGLWEOut.Value[i], ctGLWEOut.Value[i])
	}
}
