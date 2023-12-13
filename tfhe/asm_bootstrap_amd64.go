//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

func rotateSubAddAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func rotateSubAddAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// rotateSubAddAssign multiplies X^(-d) - 1 to p0, and adds it to pOut.
//
// p0 and pOut should not overlap.
func rotateSubAddAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			rotateSubAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint32)(unsafe.Pointer(&pOut)),
			)

		case uint64:
			rotateSubAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint64)(unsafe.Pointer(&pOut)),
			)
		}
		return
	}

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

func rotateSubAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func rotateSubAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// rotateSubAssign multiplies X^(-d) - 1 to p0, and writes it to pOut.
//
// p0 and pOut should not overlap.
func rotateSubAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			rotateSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint32)(unsafe.Pointer(&pOut)),
			)

		case uint64:
			rotateSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint64)(unsafe.Pointer(&pOut)),
			)
		}
		return
	}

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
