//go:build amd64 && !purego

package poly

import (
	"math"
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

// foldPolyTo converts and folds p to fpOut.
func foldPolyTo[T num.Integer](fpOut []float64, p []T) {
	if cpu.X86.HasAVX {
		var z T
		switch any(z).(type) {
		case uint32:
			foldPolyToUint32AVX2(fpOut, *(*[]uint32)(unsafe.Pointer(&p)))
			return
		case uint64:
			foldPolyToUint64AVX2(fpOut, *(*[]uint64)(unsafe.Pointer(&p)))
			return
		}
	}

	N := len(fpOut)

	var z T
	switch any(z).(type) {
	case uint:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uint)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uint)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int(w0[0]))
			wOut[1] = float64(int(w0[1]))
			wOut[2] = float64(int(w0[2]))
			wOut[3] = float64(int(w0[3]))

			wOut[4] = float64(int(w1[0]))
			wOut[5] = float64(int(w1[1]))
			wOut[6] = float64(int(w1[2]))
			wOut[7] = float64(int(w1[3]))
		}
	case uintptr:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uintptr)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uintptr)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int(w0[0]))
			wOut[1] = float64(int(w0[1]))
			wOut[2] = float64(int(w0[2]))
			wOut[3] = float64(int(w0[3]))

			wOut[4] = float64(int(w1[0]))
			wOut[5] = float64(int(w1[1]))
			wOut[6] = float64(int(w1[2]))
			wOut[7] = float64(int(w1[3]))
		}
	case uint8:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uint8)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uint8)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int8(w0[0]))
			wOut[1] = float64(int8(w0[1]))
			wOut[2] = float64(int8(w0[2]))
			wOut[3] = float64(int8(w0[3]))

			wOut[4] = float64(int8(w1[0]))
			wOut[5] = float64(int8(w1[1]))
			wOut[6] = float64(int8(w1[2]))
			wOut[7] = float64(int8(w1[3]))
		}
	case uint16:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uint16)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uint16)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int16(w0[0]))
			wOut[1] = float64(int16(w0[1]))
			wOut[2] = float64(int16(w0[2]))
			wOut[3] = float64(int16(w0[3]))

			wOut[4] = float64(int16(w1[0]))
			wOut[5] = float64(int16(w1[1]))
			wOut[6] = float64(int16(w1[2]))
			wOut[7] = float64(int16(w1[3]))
		}
	case uint32:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uint32)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uint32)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int32(w0[0]))
			wOut[1] = float64(int32(w0[1]))
			wOut[2] = float64(int32(w0[2]))
			wOut[3] = float64(int32(w0[3]))

			wOut[4] = float64(int32(w1[0]))
			wOut[5] = float64(int32(w1[1]))
			wOut[6] = float64(int32(w1[2]))
			wOut[7] = float64(int32(w1[3]))
		}
	case uint64:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]uint64)(unsafe.Pointer(&p[ii]))
			w1 := (*[4]uint64)(unsafe.Pointer(&p[ii+N/2]))
			wOut := (*[8]float64)(unsafe.Pointer(&fpOut[i]))

			wOut[0] = float64(int64(w0[0]))
			wOut[1] = float64(int64(w0[1]))
			wOut[2] = float64(int64(w0[2]))
			wOut[3] = float64(int64(w0[3]))

			wOut[4] = float64(int64(w1[0]))
			wOut[5] = float64(int64(w1[1]))
			wOut[6] = float64(int64(w1[2]))
			wOut[7] = float64(int64(w1[3]))
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
func floatModQInPlace(coeffs []float64, q float64) {
	if cpu.X86.HasAVX {
		floatModQInPlaceAVX2(coeffs, q, 1/q)
		return
	}

	N := len(coeffs)

	for i := 0; i < N; i += 8 {
		c := (*[8]float64)(unsafe.Pointer(&coeffs[i]))

		c[0] = math.Round(c[0] - q*math.Round(c[0]/q))
		c[1] = math.Round(c[1] - q*math.Round(c[1]/q))
		c[2] = math.Round(c[2] - q*math.Round(c[2]/q))
		c[3] = math.Round(c[3] - q*math.Round(c[3]/q))

		c[4] = math.Round(c[4] - q*math.Round(c[4]/q))
		c[5] = math.Round(c[5] - q*math.Round(c[5]/q))
		c[6] = math.Round(c[6] - q*math.Round(c[6]/q))
		c[7] = math.Round(c[7] - q*math.Round(c[7]/q))
	}
}

// unfoldPolyTo converts and unfolds fp to pOut.
func unfoldPolyTo[T num.Integer](pOut []T, fp []float64) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			unfoldPolyToUint32AVX2(*(*[]uint32)(unsafe.Pointer(&pOut)), fp)
			return
		case uint64:
			unfoldPolyToUint64AVX2(*(*[]uint64)(unsafe.Pointer(&pOut)), fp)
			return
		}
	}

	N := len(fp)

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		w := (*[8]float64)(unsafe.Pointer(&fp[i]))
		wOut0 := (*[4]T)(unsafe.Pointer(&pOut[ii]))
		wOut1 := (*[4]T)(unsafe.Pointer(&pOut[ii+N/2]))

		wOut0[0] = T(int64(w[0]))
		wOut0[1] = T(int64(w[1]))
		wOut0[2] = T(int64(w[2]))
		wOut0[3] = T(int64(w[3]))

		wOut1[0] = T(int64(w[4]))
		wOut1[1] = T(int64(w[5]))
		wOut1[2] = T(int64(w[6]))
		wOut1[3] = T(int64(w[7]))
	}
}

// unfoldPolyAddTo converts and unfolds fp and adds it to pOut.
func unfoldPolyAddTo[T num.Integer](pOut []T, fp []float64) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			unfoldPolyAddToUint32AVX2(*(*[]uint32)(unsafe.Pointer(&pOut)), fp)
			return
		case uint64:
			unfoldPolyAddToUint64AVX2(*(*[]uint64)(unsafe.Pointer(&pOut)), fp)
			return
		}
	}

	N := len(fp)

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		w := (*[8]float64)(unsafe.Pointer(&fp[i]))
		wOut0 := (*[4]T)(unsafe.Pointer(&pOut[ii]))
		wOut1 := (*[4]T)(unsafe.Pointer(&pOut[ii+N/2]))

		wOut0[0] += T(int64(w[0]))
		wOut0[1] += T(int64(w[1]))
		wOut0[2] += T(int64(w[2]))
		wOut0[3] += T(int64(w[3]))

		wOut1[0] += T(int64(w[4]))
		wOut1[1] += T(int64(w[5]))
		wOut1[2] += T(int64(w[6]))
		wOut1[3] += T(int64(w[7]))
	}
}

// unfoldPolySubTo converts and unfolds fp and subtracts it from pOut.
func unfoldPolySubTo[T num.Integer](pOut []T, fp []float64) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			unfoldPolySubToUint32AVX2(*(*[]uint32)(unsafe.Pointer(&pOut)), fp)
			return
		case uint64:
			unfoldPolySubToUint64AVX2(*(*[]uint64)(unsafe.Pointer(&pOut)), fp)
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
