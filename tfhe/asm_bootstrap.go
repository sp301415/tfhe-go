//go:build !(amd64 && !purego)

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// monomialDivMinusOneAddGLWEAssign multiplies X^(-d) - 1 to ct, and adds it to ctOut.
//
// ct and ctOut should not overlap.
func monomialDivMinusOneAddGLWEAssign[T Tint](ct GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	glweDimension := len(ctOut.Value) - 1
	polyDegree := ctOut.Value[0].Degree()

	if d < polyDegree {
		for i := 0; i < glweDimension+1; i++ {
			for j, jj := 0, d; jj < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] += ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
			for j, jj := polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] += -ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
		}
	} else {
		for i := 0; i < glweDimension+1; i++ {
			for j, jj := 0, d-polyDegree; jj < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] += -ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
			for j, jj := 2*polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] += ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
		}
	}
}

// monomialDivMinusOneAssign multiplies X^(-d) - 1 to p0, and writes it to pOut.
//
// p0 and pOut should not overlap.
func monomialDivMinusOneAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	polyDegree := pOut.Degree()
	if d < polyDegree {
		for j, jj := 0, d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, d-polyDegree; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := 2*polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}

// monomialDivMinusOneGLWEAssign multiplies X^(-d) - 1 to ct, and writes it to ctOut.
//
// ct and ctOut should not overlap.
func monomialDivMinusOneGLWEAssign[T Tint](ct GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	glweDimension := len(ctOut.Value) - 1
	polyDegree := ctOut.Value[0].Degree()

	if d < polyDegree {
		for i := 0; i < glweDimension+1; i++ {
			for j, jj := 0, d; jj < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] = ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
			for j, jj := polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] = -ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
		}
	} else {
		for i := 0; i < glweDimension+1; i++ {
			for j, jj := 0, d-polyDegree; jj < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] = -ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
			for j, jj := 2*polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
				ctOut.Value[i].Coeffs[j] = ct.Value[i].Coeffs[jj] - ct.Value[i].Coeffs[j]
			}
		}
	}
}
