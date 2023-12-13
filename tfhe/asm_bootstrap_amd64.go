//go:build amd64 && !purego

package tfhe

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/sys/cpu"
)

func monomialDivMinusOneAddAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialDivMinusOneAddAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialDivMinusOneAddGLWEAssign multiplies X^(-d) - 1 to ct, and adds it to ctOut.
//
// ct and ctOut should not overlap.
func monomialDivMinusOneAddGLWEAssign[T Tint](ct GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	glweDimension := len(ctOut.Value) - 1
	polyDegree := ctOut.Value[0].Degree()

	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			for i := 0; i < glweDimension+1; i++ {
				monomialDivMinusOneAddAssignUint32AVX2(
					*(*[]uint32)(unsafe.Pointer(&ct.Value[i])),
					d,
					*(*[]uint32)(unsafe.Pointer(&ctOut.Value[i])),
				)
			}

		case uint64:
			for i := 0; i < glweDimension+1; i++ {
				monomialDivMinusOneAddAssignUint64AVX2(
					*(*[]uint64)(unsafe.Pointer(&ct.Value[i])),
					d,
					*(*[]uint64)(unsafe.Pointer(&ctOut.Value[i])),
				)
			}
		}
		return
	}

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

func monomialDivMinusOneAssignUint32AVX2(p0 []uint32, d int, pOut []uint32)
func monomialDivMinusOneAssignUint64AVX2(p0 []uint64, d int, pOut []uint64)

// monomialDivMinusOneAssign multiplies X^(-d) - 1 to p0, and writes it to pOut.
//
// p0 and pOut should not overlap.
func monomialDivMinusOneAssign[T Tint](p0 poly.Poly[T], d int, pOut poly.Poly[T]) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			monomialDivMinusOneAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&p0)),
				d,
				*(*[]uint32)(unsafe.Pointer(&pOut)),
			)

		case uint64:
			monomialDivMinusOneAssignUint64AVX2(
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

// monomialDivMinusOneGLWEAssign multiplies X^(-d) - 1 to ct, and writes it to ctOut.
//
// ct and ctOut should not overlap.
func monomialDivMinusOneGLWEAssign[T Tint](ct GLWECiphertext[T], d int, ctOut GLWECiphertext[T]) {
	glweDimension := len(ctOut.Value) - 1
	polyDegree := ctOut.Value[0].Degree()

	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			for i := 0; i < glweDimension+1; i++ {
				monomialDivMinusOneAssignUint32AVX2(
					*(*[]uint32)(unsafe.Pointer(&ct.Value[i])),
					d,
					*(*[]uint32)(unsafe.Pointer(&ctOut.Value[i])),
				)
			}

		case uint64:
			for i := 0; i < glweDimension+1; i++ {
				monomialDivMinusOneAssignUint64AVX2(
					*(*[]uint64)(unsafe.Pointer(&ct.Value[i])),
					d,
					*(*[]uint64)(unsafe.Pointer(&ctOut.Value[i])),
				)
			}
		}
		return
	}

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
