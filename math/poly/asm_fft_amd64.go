//go:build amd64 && !purego

package poly

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

func fwdButterfly(uR, uI, vR, vI, wR, wI float64) (float64, float64, float64, float64) {
	vwR := vR*wR - vI*wI
	vwI := vR*wI + vI*wR
	return uR + vwR, uI + vwI, uR - vwR, uI - vwI
}

// fwdFFTInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fwdFFTInPlace(coeffs []float64, tw []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		fwdFFTInPlaceAVX2(coeffs, tw)
		return
	}

	N := len(coeffs)
	wPtr := unsafe.Pointer(&tw[0])
	wIdx := 0
	coeffsPtr := unsafe.Pointer(&coeffs[0])

	wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
	wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
	wIdx++
	for j := 0; j < N/2; j += 8 {
		u := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		v := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+N/2)*unsafe.Sizeof(float64(0))))

		u[0], u[4], v[0], v[4] = fwdButterfly(u[0], u[4], v[0], v[4], wReal, wImag)
		u[1], u[5], v[1], v[5] = fwdButterfly(u[1], u[5], v[1], v[5], wReal, wImag)
		u[2], u[6], v[2], v[6] = fwdButterfly(u[2], u[6], v[2], v[6], wReal, wImag)
		u[3], u[7], v[3], v[7] = fwdButterfly(u[3], u[7], v[3], v[7], wReal, wImag)
	}

	t := N / 2
	for m := 2; m <= N/16; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t

			wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
			wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
			wIdx++

			for j := j1; j < j2; j += 8 {
				u := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
				v := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+t)*unsafe.Sizeof(float64(0))))

				u[0], u[4], v[0], v[4] = fwdButterfly(u[0], u[4], v[0], v[4], wReal, wImag)
				u[1], u[5], v[1], v[5] = fwdButterfly(u[1], u[5], v[1], v[5], wReal, wImag)
				u[2], u[6], v[2], v[6] = fwdButterfly(u[2], u[6], v[2], v[6], wReal, wImag)
				u[3], u[7], v[3], v[7] = fwdButterfly(u[3], u[7], v[3], v[7], wReal, wImag)
			}
		}
	}

	for j := 0; j < N; j += 8 {
		wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wIdx++

		uvReal := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		uvImag := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvReal[0], uvImag[0], uvReal[2], uvImag[2] = fwdButterfly(uvReal[0], uvImag[0], uvReal[2], uvImag[2], wReal, wImag)
		uvReal[1], uvImag[1], uvReal[3], uvImag[3] = fwdButterfly(uvReal[1], uvImag[1], uvReal[3], uvImag[3], wReal, wImag)
	}

	for j := 0; j < N; j += 8 {
		wReal0 := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wImag0 := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wReal1 := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx+1)*unsafe.Sizeof(complex128(0)))))
		wImag1 := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx+1)*unsafe.Sizeof(complex128(0)))))
		wIdx += 2

		uvReal := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		uvImag := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvReal[0], uvImag[0], uvReal[1], uvImag[1] = fwdButterfly(uvReal[0], uvImag[0], uvReal[1], uvImag[1], wReal0, wImag0)
		uvReal[2], uvImag[2], uvReal[3], uvImag[3] = fwdButterfly(uvReal[2], uvImag[2], uvReal[3], uvImag[3], wReal1, wImag1)
	}
}

func invButterfly(uR, uI, vR, vI, wR, wI float64) (float64, float64, float64, float64) {
	uR, uI, vR, vI = uR+vR, uI+vI, uR-vR, uI-vI
	vwR := vR*wR - vI*wI
	vwI := vR*wI + vI*wR
	return uR, uI, vwR, vwI
}

// invFFTInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs []float64, twInv []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		invFFTInPlaceAVX2(coeffs, twInv, 2/float64(len(coeffs)))
		return
	}
	N := len(coeffs)
	wPtr := unsafe.Pointer(&twInv[0])
	wIdx := 0
	coeffsPtr := unsafe.Pointer(&coeffs[0])

	for j := 0; j < N; j += 8 {
		wReal0 := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wImag0 := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wReal1 := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx+1)*unsafe.Sizeof(complex128(0)))))
		wImag1 := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx+1)*unsafe.Sizeof(complex128(0)))))
		wIdx += 2

		uvReal := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		uvImag := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvReal[0], uvImag[0], uvReal[1], uvImag[1] = invButterfly(uvReal[0], uvImag[0], uvReal[1], uvImag[1], wReal0, wImag0)
		uvReal[2], uvImag[2], uvReal[3], uvImag[3] = invButterfly(uvReal[2], uvImag[2], uvReal[3], uvImag[3], wReal1, wImag1)
	}

	for j := 0; j < N; j += 8 {
		wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
		wIdx++

		uvReal := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		uvImag := (*[4]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvReal[0], uvImag[0], uvReal[2], uvImag[2] = invButterfly(uvReal[0], uvImag[0], uvReal[2], uvImag[2], wReal, wImag)
		uvReal[1], uvImag[1], uvReal[3], uvImag[3] = invButterfly(uvReal[1], uvImag[1], uvReal[3], uvImag[3], wReal, wImag)
	}

	t := 8
	for m := N / 16; m >= 2; m >>= 1 {
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t

			wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
			wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
			wIdx++

			for j := j1; j < j2; j += 8 {
				u := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
				v := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+t)*unsafe.Sizeof(float64(0))))

				u[0], u[4], v[0], v[4] = invButterfly(u[0], u[4], v[0], v[4], wReal, wImag)
				u[1], u[5], v[1], v[5] = invButterfly(u[1], u[5], v[1], v[5], wReal, wImag)
				u[2], u[6], v[2], v[6] = invButterfly(u[2], u[6], v[2], v[6], wReal, wImag)
				u[3], u[7], v[3], v[7] = invButterfly(u[3], u[7], v[3], v[7], wReal, wImag)
			}
		}
		t <<= 1
	}

	scale := float64(N / 2)
	wReal := real(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
	wImag := imag(*(*complex128)(unsafe.Pointer(uintptr(wPtr) + uintptr(wIdx)*unsafe.Sizeof(complex128(0)))))
	for j := 0; j < N/2; j += 8 {
		u := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j)*unsafe.Sizeof(float64(0))))
		v := (*[8]float64)(unsafe.Pointer(uintptr(coeffsPtr) + uintptr(j+N/2)*unsafe.Sizeof(float64(0))))

		u[0], u[4], v[0], v[4] = invButterfly(u[0], u[4], v[0], v[4], wReal, wImag)
		u[1], u[5], v[1], v[5] = invButterfly(u[1], u[5], v[1], v[5], wReal, wImag)
		u[2], u[6], v[2], v[6] = invButterfly(u[2], u[6], v[2], v[6], wReal, wImag)
		u[3], u[7], v[3], v[7] = invButterfly(u[3], u[7], v[3], v[7], wReal, wImag)

		u[0] /= scale
		u[1] /= scale
		u[2] /= scale
		u[3] /= scale

		u[4] /= scale
		u[5] /= scale
		u[6] /= scale
		u[7] /= scale

		v[0] /= scale
		v[1] /= scale
		v[2] /= scale
		v[3] /= scale

		v[4] /= scale
		v[5] /= scale
		v[6] /= scale
		v[7] /= scale
	}
}
