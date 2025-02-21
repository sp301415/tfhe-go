//go:build amd64 && !purego

package poly

import (
	"math"
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

// convertPolyToFourierPolyAssign converts and folds p to fpOut.
func convertPolyToFourierPolyAssign[T num.Integer](p []T, fpOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
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
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(int(p[ii+0]))
			fpOut[i+1] = float64(int(p[ii+1]))
			fpOut[i+2] = float64(int(p[ii+2]))
			fpOut[i+3] = float64(int(p[ii+3]))

			fpOut[i+4] = float64(int(p[ii+0+N/2]))
			fpOut[i+5] = float64(int(p[ii+1+N/2]))
			fpOut[i+6] = float64(int(p[ii+2+N/2]))
			fpOut[i+7] = float64(int(p[ii+3+N/2]))
		}
	case uint8:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(int8(p[ii+0]))
			fpOut[i+1] = float64(int8(p[ii+1]))
			fpOut[i+2] = float64(int8(p[ii+2]))
			fpOut[i+3] = float64(int8(p[ii+3]))

			fpOut[i+4] = float64(int8(p[ii+0+N/2]))
			fpOut[i+5] = float64(int8(p[ii+1+N/2]))
			fpOut[i+6] = float64(int8(p[ii+2+N/2]))
			fpOut[i+7] = float64(int8(p[ii+3+N/2]))
		}
	case uint16:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(int16(p[ii+0]))
			fpOut[i+1] = float64(int16(p[ii+1]))
			fpOut[i+2] = float64(int16(p[ii+2]))
			fpOut[i+3] = float64(int16(p[ii+3]))

			fpOut[i+4] = float64(int16(p[ii+0+N/2]))
			fpOut[i+5] = float64(int16(p[ii+1+N/2]))
			fpOut[i+6] = float64(int16(p[ii+2+N/2]))
			fpOut[i+7] = float64(int16(p[ii+3+N/2]))
		}
	case uint32:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(int32(p[ii+0]))
			fpOut[i+1] = float64(int32(p[ii+1]))
			fpOut[i+2] = float64(int32(p[ii+2]))
			fpOut[i+3] = float64(int32(p[ii+3]))

			fpOut[i+4] = float64(int32(p[ii+0+N/2]))
			fpOut[i+5] = float64(int32(p[ii+1+N/2]))
			fpOut[i+6] = float64(int32(p[ii+2+N/2]))
			fpOut[i+7] = float64(int32(p[ii+3+N/2]))
		}
	case uint64:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(int64(p[ii+0]))
			fpOut[i+1] = float64(int64(p[ii+1]))
			fpOut[i+2] = float64(int64(p[ii+2]))
			fpOut[i+3] = float64(int64(p[ii+3]))

			fpOut[i+4] = float64(int64(p[ii+0+N/2]))
			fpOut[i+5] = float64(int64(p[ii+1+N/2]))
			fpOut[i+6] = float64(int64(p[ii+2+N/2]))
			fpOut[i+7] = float64(int64(p[ii+3+N/2]))
		}
	default:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			fpOut[i+0] = float64(p[ii+0])
			fpOut[i+1] = float64(p[ii+1])
			fpOut[i+2] = float64(p[ii+2])
			fpOut[i+3] = float64(p[ii+3])

			fpOut[i+4] = float64(p[ii+0+N/2])
			fpOut[i+5] = float64(p[ii+1+N/2])
			fpOut[i+6] = float64(p[ii+2+N/2])
			fpOut[i+7] = float64(p[ii+3+N/2])
		}
	}
}

// floatModQInPlace computes coeffs mod Q in place.
func floatModQInPlace(coeffs []float64, Q float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		floatModQInPlaceAVX2(coeffs, Q, 1/Q)
		return
	}

	N := len(coeffs)
	for i := 0; i < N; i++ {
		coeffs[i] = math.Round(coeffs[i] - Q*math.Round(coeffs[i]/Q))
	}
}

// convertFourierPolyToPolyAssign converts and unfolds fp to pOut.
func convertFourierPolyToPolyAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
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

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		pOut[ii+0] = T(int64(fp[i+0]))
		pOut[ii+1] = T(int64(fp[i+1]))
		pOut[ii+2] = T(int64(fp[i+2]))
		pOut[ii+3] = T(int64(fp[i+3]))

		pOut[ii+0+N/2] = T(int64(fp[i+4]))
		pOut[ii+1+N/2] = T(int64(fp[i+5]))
		pOut[ii+2+N/2] = T(int64(fp[i+6]))
		pOut[ii+3+N/2] = T(int64(fp[i+7]))
	}
}

// convertFourierPolyToPolyAddAssign converts and unfolds fp and adds it to pOut.
func convertFourierPolyToPolyAddAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
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

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		pOut[ii+0] += T(int64(fp[i+0]))
		pOut[ii+1] += T(int64(fp[i+1]))
		pOut[ii+2] += T(int64(fp[i+2]))
		pOut[ii+3] += T(int64(fp[i+3]))

		pOut[ii+0+N/2] += T(int64(fp[i+4]))
		pOut[ii+1+N/2] += T(int64(fp[i+5]))
		pOut[ii+2+N/2] += T(int64(fp[i+6]))
		pOut[ii+3+N/2] += T(int64(fp[i+7]))
	}
}

// convertFourierPolyToPolySubAssign converts and unfolds fp and subtracts it from pOut.
func convertFourierPolyToPolySubAssign[T num.Integer](fp []float64, pOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
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

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		pOut[ii+0] -= T(int64(fp[i+0]))
		pOut[ii+1] -= T(int64(fp[i+1]))
		pOut[ii+2] -= T(int64(fp[i+2]))
		pOut[ii+3] -= T(int64(fp[i+3]))

		pOut[ii+0+N/2] -= T(int64(fp[i+4]))
		pOut[ii+1+N/2] -= T(int64(fp[i+5]))
		pOut[ii+2+N/2] -= T(int64(fp[i+6]))
		pOut[ii+3+N/2] -= T(int64(fp[i+7]))
	}
}
