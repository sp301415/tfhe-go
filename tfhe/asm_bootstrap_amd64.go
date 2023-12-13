//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

func monomialMulSubAddAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialMulSubAddAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialMulSubAddAssign multiplies X^d - 1 to p0, and adds it to pOut.
//
// d is assumed to be in [-2N, 0]. p0 and pOut should not overlap.
func monomialMulSubAddAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			monomialMulSubAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint32)(unsafe.Pointer(&pOut)),
			)

		case uint64:
			monomialMulSubAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint64)(unsafe.Pointer(&pOut)),
			)
		}
		return
	}

	polyDegree := pOut.Degree()
	if -polyDegree <= d {
		for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, -polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := 2*polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] += p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}

func monomialMulSubAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialMulSubAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialMulSubAssign multiplies X^(-d) - 1 to p0, and writes it to pOut.
//
// d is assumed to be in [-2N, 0]. p0 and pOut should not overlap.
func monomialMulSubAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			monomialMulSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint32)(unsafe.Pointer(&pOut)),
			)

		case uint64:
			monomialMulSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint64)(unsafe.Pointer(&pOut)),
			)
		}
		return
	}

	polyDegree := pOut.Degree()
	if -polyDegree <= d {
		for j, jj := 0, -d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
	} else {
		for j, jj := 0, -polyDegree-d; jj < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = -p0.Coeffs[jj] - p0.Coeffs[j]
		}
		for j, jj := 2*polyDegree+d, 0; j < polyDegree; j, jj = j+1, jj+1 {
			pOut.Coeffs[j] = p0.Coeffs[jj] - p0.Coeffs[j]
		}
	}
}
