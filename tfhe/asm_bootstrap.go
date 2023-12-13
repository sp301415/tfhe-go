//go:build !(amd64 && !purego)

package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
)

// rotateSubAddAssign multiplies X^(-d) - 1 to p0, and adds it to pOut.
//
// p0 and pOut should not overlap.
func rotateSubAddAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	polyDegree := pOut.Degree()
	if d < polyDegree {
		for j, jj := 0, d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, d-polyDegree; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := 2*polyDegree-d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}

// rotateSubAssign multiplies X^(-d) - 1 to p0, and writes it to pOut.
//
// p0 and pOut should not overlap.
func rotateSubAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
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
