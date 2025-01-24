//go:build amd64 && !purego

package poly

import (
	"math"
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

func convertPolyToFourierPolyAssignUint32AVX2(p []uint32, fpOut []float64)
func convertPolyToFourierPolyAssignUint64AVX2(p []uint64, fpOut []float64)

// convertPolyToFourierPolyAssign converts and folds p to fpOut.
func convertPolyToFourierPolyAssign[T num.Integer](p []T, fpOut []float64) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			convertPolyToFourierPolyAssignUint32AVX2(*(*[]uint32)(unsafe.Pointer(&p)), fpOut)
			return
		case uint64:
			convertPolyToFourierPolyAssignUint64AVX2(*(*[]uint64)(unsafe.Pointer(&p)), fpOut)
			return
		}
	}

	N := len(fpOut)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(int(p[jj+0]))
			fpOut[j+1] = float64(int(p[jj+1]))
			fpOut[j+2] = float64(int(p[jj+2]))
			fpOut[j+3] = float64(int(p[jj+3]))

			fpOut[j+4] = float64(int(p[jj+0+N/2]))
			fpOut[j+5] = float64(int(p[jj+1+N/2]))
			fpOut[j+6] = float64(int(p[jj+2+N/2]))
			fpOut[j+7] = float64(int(p[jj+3+N/2]))
		}
	case uint8:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(int8(p[jj+0]))
			fpOut[j+1] = float64(int8(p[jj+1]))
			fpOut[j+2] = float64(int8(p[jj+2]))
			fpOut[j+3] = float64(int8(p[jj+3]))

			fpOut[j+4] = float64(int8(p[jj+0+N/2]))
			fpOut[j+5] = float64(int8(p[jj+1+N/2]))
			fpOut[j+6] = float64(int8(p[jj+2+N/2]))
			fpOut[j+7] = float64(int8(p[jj+3+N/2]))
		}
	case uint16:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(int16(p[jj+0]))
			fpOut[j+1] = float64(int16(p[jj+1]))
			fpOut[j+2] = float64(int16(p[jj+2]))
			fpOut[j+3] = float64(int16(p[jj+3]))

			fpOut[j+4] = float64(int16(p[jj+0+N/2]))
			fpOut[j+5] = float64(int16(p[jj+1+N/2]))
			fpOut[j+6] = float64(int16(p[jj+2+N/2]))
			fpOut[j+7] = float64(int16(p[jj+3+N/2]))
		}
	case uint32:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(int32(p[jj+0]))
			fpOut[j+1] = float64(int32(p[jj+1]))
			fpOut[j+2] = float64(int32(p[jj+2]))
			fpOut[j+3] = float64(int32(p[jj+3]))

			fpOut[j+4] = float64(int32(p[jj+0+N/2]))
			fpOut[j+5] = float64(int32(p[jj+1+N/2]))
			fpOut[j+6] = float64(int32(p[jj+2+N/2]))
			fpOut[j+7] = float64(int32(p[jj+3+N/2]))
		}
	case uint64:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(int64(p[jj+0]))
			fpOut[j+1] = float64(int64(p[jj+1]))
			fpOut[j+2] = float64(int64(p[jj+2]))
			fpOut[j+3] = float64(int64(p[jj+3]))

			fpOut[j+4] = float64(int64(p[jj+0+N/2]))
			fpOut[j+5] = float64(int64(p[jj+1+N/2]))
			fpOut[j+6] = float64(int64(p[jj+2+N/2]))
			fpOut[j+7] = float64(int64(p[jj+3+N/2]))
		}
	default:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut[j+0] = float64(p[jj+0])
			fpOut[j+1] = float64(p[jj+1])
			fpOut[j+2] = float64(p[jj+2])
			fpOut[j+3] = float64(p[jj+3])

			fpOut[j+4] = float64(p[jj+0+N/2])
			fpOut[j+5] = float64(p[jj+1+N/2])
			fpOut[j+6] = float64(p[jj+2+N/2])
			fpOut[j+7] = float64(p[jj+3+N/2])
		}
	}
}

func floatModQInPlaceAVX2(coeffs []float64, Q, QInv float64)

// floatModQInPlace computes coeffs mod Q in place.
func floatModQInPlace(coeffs []float64, Q float64) {
	if cpu.X86.HasAVX2 {
		floatModQInPlaceAVX2(coeffs, Q, 1/Q)
		return
	}

	for i := range coeffs {
		coeffs[i] = coeffs[i] / Q
		coeffs[i] = coeffs[i] - math.Round(coeffs[i])
		coeffs[i] = math.Round(coeffs[i] * Q)
	}
}

func convertFourierPolyToPolyAssignUint32AVX2(fp []float64, pOut []uint32)
func convertFourierPolyToPolyAssignUint64AVX2(fp []float64, pOut []uint64)

// convertFourierPolyToPolyAssign converts and unfolds fp to pOut.
func convertFourierPolyToPolyAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			convertFourierPolyToPolyAssignUint32AVX2(fp, *(*[]uint32)(unsafe.Pointer(&pOut)))
			return
		case uint64:
			convertFourierPolyToPolyAssignUint64AVX2(fp, *(*[]uint64)(unsafe.Pointer(&pOut)))
			return
		}
	}

	N := len(fp)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut[jj+0] = T(int64(fp[j+0]))
		pOut[jj+1] = T(int64(fp[j+1]))
		pOut[jj+2] = T(int64(fp[j+2]))
		pOut[jj+3] = T(int64(fp[j+3]))

		pOut[jj+0+N/2] = T(int64(fp[j+4]))
		pOut[jj+1+N/2] = T(int64(fp[j+5]))
		pOut[jj+2+N/2] = T(int64(fp[j+6]))
		pOut[jj+3+N/2] = T(int64(fp[j+7]))
	}
}

func convertFourierPolyToPolyAddAssignUint32AVX2(fp []float64, pOut []uint32)
func convertFourierPolyToPolyAddAssignUint64AVX2(fp []float64, pOut []uint64)

// convertFourierPolyToPolyAddAssign converts and unfolds fp and adds it to pOut.
func convertFourierPolyToPolyAddAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			convertFourierPolyToPolyAddAssignUint32AVX2(fp, *(*[]uint32)(unsafe.Pointer(&pOut)))
			return
		case uint64:
			convertFourierPolyToPolyAddAssignUint64AVX2(fp, *(*[]uint64)(unsafe.Pointer(&pOut)))
			return
		}
	}

	N := len(fp)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut[jj+0] += T(int64(fp[j+0]))
		pOut[jj+1] += T(int64(fp[j+1]))
		pOut[jj+2] += T(int64(fp[j+2]))
		pOut[jj+3] += T(int64(fp[j+3]))

		pOut[jj+0+N/2] += T(int64(fp[j+4]))
		pOut[jj+1+N/2] += T(int64(fp[j+5]))
		pOut[jj+2+N/2] += T(int64(fp[j+6]))
		pOut[jj+3+N/2] += T(int64(fp[j+7]))
	}
}

func convertFourierPolyToPolySubAssignUint32AVX2(fp []float64, pOut []uint32)
func convertFourierPolyToPolySubAssignUint64AVX2(fp []float64, pOut []uint64)

// convertFourierPolyToPolySubAssign converts and unfolds fp and subtracts it from pOut.
func convertFourierPolyToPolySubAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			convertFourierPolyToPolySubAssignUint32AVX2(fp, *(*[]uint32)(unsafe.Pointer(&pOut)))
			return
		case uint64:
			convertFourierPolyToPolySubAssignUint64AVX2(fp, *(*[]uint64)(unsafe.Pointer(&pOut)))
			return
		}
	}

	N := len(fp)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut[jj+0] -= T(int64(fp[j+0]))
		pOut[jj+1] -= T(int64(fp[j+1]))
		pOut[jj+2] -= T(int64(fp[j+2]))
		pOut[jj+3] -= T(int64(fp[j+3]))

		pOut[jj+0+N/2] -= T(int64(fp[j+4]))
		pOut[jj+1+N/2] -= T(int64(fp[j+5]))
		pOut[jj+2+N/2] -= T(int64(fp[j+6]))
		pOut[jj+3+N/2] -= T(int64(fp[j+7]))
	}
}
