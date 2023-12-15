//go:build !(amd64 && !purego)

package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
)

// monomialSubOneMulAssign multiplies X^d - 1 to p0, and writes it to pOut.
//
// d is assumed to be in [-N, N]. p0 and pOut should not overlap.
func monomialSubOneMulAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	polyDegree := pOut.Degree()
	if d > 0 {
		for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}

// monomialSubOneMulAddAssign multiplies X^d - 1 to p0, and adds it to pOut.
//
// d is assumed to be in [-N, N]. p0 and pOut should not overlap.
func monomialSubOneMulAddAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	polyDegree := pOut.Degree()
	if d > 0 {
		for j, jj := 0, polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}
