//go:build !(amd64 && !purego)

package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
)

// monomialSubOneMulAssign computes pOut = (X^d - 1) * p0.
//
// d should be in [0, 2N), and p0 and pOut should not overlap.
func monomialSubOneMulAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	polyDegree := pOut.Degree()
	if d < polyDegree {
		for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
	} else {
		for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
	}
}

// monomialSubOneMulAddAssign computes pOut += (X^d - 1) * p0.
//
// d should be in [0, 2N), and p0 and pOut should not overlap.
func monomialSubOneMulAddAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	polyDegree := pOut.Degree()
	if d < polyDegree {
		for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
	} else {
		for i, ii := 0, 2*polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
	}
}
