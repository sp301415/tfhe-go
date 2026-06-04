//go:build !(amd64 && !purego)

package poly

import "unsafe"

func fwdButterfly(uR, uI, vR, vI, wR, wI float64) (float64, float64, float64, float64) {
	vwR := vR*wR - vI*wI
	vwI := vR*wI + vI*wR
	return uR + vwR, uI + vwI, uR - vwR, uI - vwI
}

// fwdFFTInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fwdFFTInPlace(coeffs []float64, tw []complex128) {
	N := len(coeffs)
	LF := unsafe.Sizeof(float64(0))
	LC := unsafe.Sizeof(complex128(0))

	r := unsafe.Pointer(&tw[:1][0])
	wIdx := 0
	v := unsafe.Pointer(&coeffs[:1][0])

	wReal := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
	wImag := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
	wIdx++
	for j := 0; j < N/2; j += 8 {
		u := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))
		v := (*[8]float64)(unsafe.Add(v, uintptr(j+N/2)*LF))

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

			wR := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
			wI := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
			wIdx++

			for j := j1; j < j2; j += 8 {
				u := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))
				v := (*[8]float64)(unsafe.Add(v, uintptr(j+t)*LF))

				u[0], u[4], v[0], v[4] = fwdButterfly(u[0], u[4], v[0], v[4], wR, wI)
				u[1], u[5], v[1], v[5] = fwdButterfly(u[1], u[5], v[1], v[5], wR, wI)
				u[2], u[6], v[2], v[6] = fwdButterfly(u[2], u[6], v[2], v[6], wR, wI)
				u[3], u[7], v[3], v[7] = fwdButterfly(u[3], u[7], v[3], v[7], wR, wI)
			}
		}
	}

	for j := 0; j < N; j += 8 {
		wR := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wI := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wIdx++

		uvR := (*[4]float64)(unsafe.Add(v, uintptr(j)*LF))
		uvI := (*[4]float64)(unsafe.Add(v, uintptr(j+4)*LF))

		uvR[0], uvI[0], uvR[2], uvI[2] = fwdButterfly(uvR[0], uvI[0], uvR[2], uvI[2], wR, wI)
		uvR[1], uvI[1], uvR[3], uvI[3] = fwdButterfly(uvR[1], uvI[1], uvR[3], uvI[3], wR, wI)
	}

	for j := 0; j < N; j += 8 {
		wR0 := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wI0 := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wR1 := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx+1)*LC)))
		wI1 := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx+1)*LC)))
		wIdx += 2

		uvR := (*[4]float64)(unsafe.Add(v, uintptr(j)*LF))
		uvI := (*[4]float64)(unsafe.Add(v, uintptr(j+4)*LF))

		uvR[0], uvI[0], uvR[1], uvI[1] = fwdButterfly(uvR[0], uvI[0], uvR[1], uvI[1], wR0, wI0)
		uvR[2], uvI[2], uvR[3], uvI[3] = fwdButterfly(uvR[2], uvI[2], uvR[3], uvI[3], wR1, wI1)
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
	N := len(coeffs)
	LF := unsafe.Sizeof(float64(0))
	LC := unsafe.Sizeof(complex128(0))

	r := unsafe.Pointer(&twInv[:1][0])
	wIdx := 0
	v := unsafe.Pointer(&coeffs[:1][0])

	for j := 0; j < N; j += 8 {
		wR0 := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wI0 := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wR1 := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx+1)*LC)))
		wI1 := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx+1)*LC)))
		wIdx += 2

		uvR := (*[4]float64)(unsafe.Add(v, uintptr(j)*unsafe.Sizeof(float64(0))))
		uvI := (*[4]float64)(unsafe.Add(v, uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvR[0], uvI[0], uvR[1], uvI[1] = invButterfly(uvR[0], uvI[0], uvR[1], uvI[1], wR0, wI0)
		uvR[2], uvI[2], uvR[3], uvI[3] = invButterfly(uvR[2], uvI[2], uvR[3], uvI[3], wR1, wI1)
	}

	for j := 0; j < N; j += 8 {
		wR := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wI := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
		wIdx++

		uvR := (*[4]float64)(unsafe.Add(v, uintptr(j)*unsafe.Sizeof(float64(0))))
		uvI := (*[4]float64)(unsafe.Add(v, uintptr(j+4)*unsafe.Sizeof(float64(0))))

		uvR[0], uvI[0], uvR[2], uvI[2] = invButterfly(uvR[0], uvI[0], uvR[2], uvI[2], wR, wI)
		uvR[1], uvI[1], uvR[3], uvI[3] = invButterfly(uvR[1], uvI[1], uvR[3], uvI[3], wR, wI)
	}

	t := 8
	for m := N / 16; m >= 2; m >>= 1 {
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t

			wR := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
			wI := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
			wIdx++

			for j := j1; j < j2; j += 8 {
				u := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))
				v := (*[8]float64)(unsafe.Add(v, uintptr(j+t)*LF))

				u[0], u[4], v[0], v[4] = invButterfly(u[0], u[4], v[0], v[4], wR, wI)
				u[1], u[5], v[1], v[5] = invButterfly(u[1], u[5], v[1], v[5], wR, wI)
				u[2], u[6], v[2], v[6] = invButterfly(u[2], u[6], v[2], v[6], wR, wI)
				u[3], u[7], v[3], v[7] = invButterfly(u[3], u[7], v[3], v[7], wR, wI)
			}
		}
		t <<= 1
	}

	scale := float64(N / 2)
	wR := real(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
	wI := imag(*(*complex128)(unsafe.Add(r, uintptr(wIdx)*LC)))
	for j := 0; j < N/2; j += 8 {
		u := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))
		v := (*[8]float64)(unsafe.Add(v, uintptr(j+N/2)*LF))

		u[0], u[4], v[0], v[4] = invButterfly(u[0], u[4], v[0], v[4], wR, wI)
		u[1], u[5], v[1], v[5] = invButterfly(u[1], u[5], v[1], v[5], wR, wI)
		u[2], u[6], v[2], v[6] = invButterfly(u[2], u[6], v[2], v[6], wR, wI)
		u[3], u[7], v[3], v[7] = invButterfly(u[3], u[7], v[3], v[7], wR, wI)

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
