//go:build !(amd64 && !purego)

package poly

import (
	"math"
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
)

// foldPolyTo converts and folds p to fpOut.
func foldPolyTo[T num.Integer](fpOut []float64, p []T) {
	N := len(fpOut)
	ptr := unsafe.Pointer(&p[0])
	ptrOut := unsafe.Pointer(&fpOut[0])

	var z T
	switch any(z).(type) {
	case uint:
		for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

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
			w0 := (*[4]T)(unsafe.Add(ptr, uintptr(ii)*unsafe.Sizeof(T(0))))
			w1 := (*[4]T)(unsafe.Add(ptr, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))
			wOut := (*[8]float64)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(float64(0))))

			wOut[0] = float64(w0[0])
			wOut[1] = float64(w0[1])
			wOut[2] = float64(w0[2])
			wOut[3] = float64(w0[3])

			wOut[4] = float64(w1[0])
			wOut[5] = float64(w1[1])
			wOut[6] = float64(w1[2])
			wOut[7] = float64(w1[3])
		}
	}
}

// floatModQInPlace computes coeffs mod Q in place.
func floatModQInPlace(coeffs []float64, q float64) {
	N := len(coeffs)
	ptr := unsafe.Pointer(&coeffs[0])

	for i := 0; i < N; i += 8 {
		c := (*[8]float64)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(float64(0))))

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
	N := len(fp)
	ptr := unsafe.Pointer(&fp[0])
	ptrOut := unsafe.Pointer(&pOut[0])

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		w := (*[8]float64)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(float64(0))))
		wOut0 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii)*unsafe.Sizeof(T(0))))
		wOut1 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))

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
	N := len(fp)
	ptr := unsafe.Pointer(&fp[0])
	ptrOut := unsafe.Pointer(&pOut[0])

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		w := (*[8]float64)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(float64(0))))
		wOut0 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii)*unsafe.Sizeof(T(0))))
		wOut1 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))

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
	N := len(fp)
	ptr := unsafe.Pointer(&fp[0])
	ptrOut := unsafe.Pointer(&pOut[0])

	for i, ii := 0, 0; i < N; i, ii = i+8, ii+4 {
		w := (*[8]float64)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(float64(0))))
		wOut0 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii)*unsafe.Sizeof(T(0))))
		wOut1 := (*[4]T)(unsafe.Add(ptrOut, uintptr(ii+N/2)*unsafe.Sizeof(T(0))))

		wOut0[0] -= T(int64(w[0]))
		wOut0[1] -= T(int64(w[1]))
		wOut0[2] -= T(int64(w[2]))
		wOut0[3] -= T(int64(w[3]))

		wOut1[0] -= T(int64(w[4]))
		wOut1[1] -= T(int64(w[5]))
		wOut1[2] -= T(int64(w[6]))
		wOut1[3] -= T(int64(w[7]))
	}
}
