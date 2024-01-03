//go:build amd64 && !purego

package poly

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

func monomialSubOneMulAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialSubOneMulAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialSubOneMulAssign multiplies X^d - 1 to p0, and writes it to pOut.
//
// d is assumed to be in [-N, N]. p0 and pOut should not overlap.
func monomialSubOneMulAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			monomialSubOneMulAssignUint32AVX2(*(*[]uint32)(unsafe.Pointer(&p0)), d, *(*[]uint32)(unsafe.Pointer(&pOut)))
			return
		case uint64:
			monomialSubOneMulAssignUint64AVX2(*(*[]uint64)(unsafe.Pointer(&p0)), d, *(*[]uint64)(unsafe.Pointer(&pOut)))
			return
		}
	}

	polyDegree := pOut.Degree()
	if d < polyDegree {
		for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii] - p0.Coeffs[i]
		}
	} else {
		for i, ii := 0, (polyDegree<<1)-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] = -p0.Coeffs[ii] - p0.Coeffs[i]
		}
	}
}

func monomialSubOneMulAddAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialSubOneMulAddAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialSubOneMulAddAssign multiplies X^d - 1 to p0, and adds it to pOut.
//
// d should to be in [0, 2N), and p0 and pOut should not overlap.
func monomialSubOneMulAddAssign[T num.Integer](p0 Poly[T], d int, pOut Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			monomialSubOneMulAddAssignUint32AVX2(*(*[]uint32)(unsafe.Pointer(&p0)), d, *(*[]uint32)(unsafe.Pointer(&pOut)))
			return
		case uint64:
			monomialSubOneMulAddAssignUint64AVX2(*(*[]uint64)(unsafe.Pointer(&p0)), d, *(*[]uint64)(unsafe.Pointer(&pOut)))
			return
		}
	}

	polyDegree := pOut.Degree()
	if d < polyDegree {
		for i, ii := 0, polyDegree-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
	} else {
		for i, ii := 0, (polyDegree<<1)-d; ii < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += p0.Coeffs[ii] - p0.Coeffs[i]
		}
		for i, ii := d-polyDegree, 0; i < polyDegree; i, ii = i+1, ii+1 {
			pOut.Coeffs[i] += -p0.Coeffs[ii] - p0.Coeffs[i]
		}
	}
}
