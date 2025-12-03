//go:build !(amd64 && !purego)

package poly

import (
	"unsafe"
)

// addCmplxTo computes vOut = v0 + v1.
func addCmplxTo(vOut, v0, v1 []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w0 := (*[8]float64)(unsafe.Pointer(uintptr(ptr0) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w1 := (*[8]float64)(unsafe.Pointer(uintptr(ptr1) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] = w0[0] + w1[0]
		wOut[1] = w0[1] + w1[1]
		wOut[2] = w0[2] + w1[2]
		wOut[3] = w0[3] + w1[3]

		wOut[4] = w0[4] + w1[4]
		wOut[5] = w0[5] + w1[5]
		wOut[6] = w0[6] + w1[6]
		wOut[7] = w0[7] + w1[7]
	}
}

// subCmplxTo computes vOut = v0 - v1.
func subCmplxTo(vOut, v0, v1 []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w0 := (*[8]float64)(unsafe.Pointer(uintptr(ptr0) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w1 := (*[8]float64)(unsafe.Pointer(uintptr(ptr1) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] = w0[0] - w1[0]
		wOut[1] = w0[1] - w1[1]
		wOut[2] = w0[2] - w1[2]
		wOut[3] = w0[3] - w1[3]

		wOut[4] = w0[4] - w1[4]
		wOut[5] = w0[5] - w1[5]
		wOut[6] = w0[6] - w1[6]
		wOut[7] = w0[7] - w1[7]
	}
}

// negCmplxTo computes vOut = -v.
func negCmplxTo(vOut, v []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] = -w[0]
		wOut[1] = -w[1]
		wOut[2] = -w[2]
		wOut[3] = -w[3]

		wOut[4] = -w[4]
		wOut[5] = -w[5]
		wOut[6] = -w[6]
		wOut[7] = -w[7]
	}
}

// floatMulCmplxTo computes vOut = c * v.
func floatMulCmplxTo(vOut, v []float64, c float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] = c * w[0]
		wOut[1] = c * w[1]
		wOut[2] = c * w[2]
		wOut[3] = c * w[3]

		wOut[4] = c * w[4]
		wOut[5] = c * w[5]
		wOut[6] = c * w[6]
		wOut[7] = c * w[7]
	}
}

// floatMulAddCmplxTo computes vOut += c * v.
func floatMulAddCmplxTo(vOut, v []float64, c float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] += c * w[0]
		wOut[1] += c * w[1]
		wOut[2] += c * w[2]
		wOut[3] += c * w[3]

		wOut[4] += c * w[4]
		wOut[5] += c * w[5]
		wOut[6] += c * w[6]
		wOut[7] += c * w[7]
	}
}

// floatMulSubCmplxTo computes vOut -= c * v.
func floatMulSubCmplxTo(vOut, v []float64, c float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] -= c * w[0]
		wOut[1] -= c * w[1]
		wOut[2] -= c * w[2]
		wOut[3] -= c * w[3]

		wOut[4] -= c * w[4]
		wOut[5] -= c * w[5]
		wOut[6] -= c * w[6]
		wOut[7] -= c * w[7]
	}
}

// cmplxMulCmplxTo computes vOut = c * v.
func cmplxMulCmplxTo(vOut, v []float64, c complex128) {
	cR, cI := real(c), imag(c)

	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] = w[0]*cR - w[4]*cI
		wOut[1] = w[1]*cR - w[5]*cI
		wOut[2] = w[2]*cR - w[6]*cI
		wOut[3] = w[3]*cR - w[7]*cI

		wOut[4] = w[0]*cI + w[4]*cR
		wOut[5] = w[1]*cI + w[5]*cR
		wOut[6] = w[2]*cI + w[6]*cR
		wOut[7] = w[3]*cI + w[7]*cR
	}
}

// cmplxMulAddCmplxTo computes vOut += c * v.
func cmplxMulAddCmplxTo(vOut, v []float64, c complex128) {
	cR, cI := real(c), imag(c)

	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] += w[0]*cR - w[4]*cI
		wOut[1] += w[1]*cR - w[5]*cI
		wOut[2] += w[2]*cR - w[6]*cI
		wOut[3] += w[3]*cR - w[7]*cI

		wOut[4] += w[0]*cI + w[4]*cR
		wOut[5] += w[1]*cI + w[5]*cR
		wOut[6] += w[2]*cI + w[6]*cR
		wOut[7] += w[3]*cI + w[7]*cR
	}
}

// cmplxMulSubCmplxTo computes vOut -= c * v.
func cmplxMulSubCmplxTo(vOut, v []float64, c complex128) {
	cR, cI := real(c), imag(c)

	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w := (*[8]float64)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*unsafe.Sizeof(float64(0))))

		wOut[0] -= w[0]*cR - w[4]*cI
		wOut[1] -= w[1]*cR - w[5]*cI
		wOut[2] -= w[2]*cR - w[6]*cI
		wOut[3] -= w[3]*cR - w[7]*cI

		wOut[4] -= w[0]*cI + w[4]*cR
		wOut[5] -= w[1]*cI + w[5]*cR
		wOut[6] -= w[2]*cI + w[6]*cR
		wOut[7] -= w[3]*cI + w[7]*cR
	}
}

// mulCmplxTo computes vOut = v0 * v1.
func mulCmplxTo(vOut, v0, v1 []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	var vOutR, vOutI float64
	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w0 := (*[8]float64)(unsafe.Pointer(uintptr(ptr0) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w1 := (*[8]float64)(unsafe.Pointer(uintptr(ptr1) + uintptr(i)*unsafe.Sizeof(float64(0))))

		vOutR = w0[0]*w1[0] - w0[4]*w1[4]
		vOutI = w0[0]*w1[4] + w0[4]*w1[0]
		wOut[0], wOut[4] = vOutR, vOutI

		vOutR = w0[1]*w1[1] - w0[5]*w1[5]
		vOutI = w0[1]*w1[5] + w0[5]*w1[1]
		wOut[1], wOut[5] = vOutR, vOutI

		vOutR = w0[2]*w1[2] - w0[6]*w1[6]
		vOutI = w0[2]*w1[6] + w0[6]*w1[2]
		wOut[2], wOut[6] = vOutR, vOutI

		vOutR = w0[3]*w1[3] - w0[7]*w1[7]
		vOutI = w0[3]*w1[7] + w0[7]*w1[3]
		wOut[3], wOut[7] = vOutR, vOutI
	}
}

// mulAddCmplxTo computes vOut += v0 * v1.
func mulAddCmplxTo(vOut, v0, v1 []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	var vOutR, vOutI float64
	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w0 := (*[8]float64)(unsafe.Pointer(uintptr(ptr0) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w1 := (*[8]float64)(unsafe.Pointer(uintptr(ptr1) + uintptr(i)*unsafe.Sizeof(float64(0))))

		vOutR = wOut[0] + (w0[0]*w1[0] - w0[4]*w1[4])
		vOutI = wOut[4] + (w0[0]*w1[4] + w0[4]*w1[0])
		wOut[0], wOut[4] = vOutR, vOutI

		vOutR = wOut[1] + (w0[1]*w1[1] - w0[5]*w1[5])
		vOutI = wOut[5] + (w0[1]*w1[5] + w0[5]*w1[1])
		wOut[1], wOut[5] = vOutR, vOutI

		vOutR = wOut[2] + (w0[2]*w1[2] - w0[6]*w1[6])
		vOutI = wOut[6] + (w0[2]*w1[6] + w0[6]*w1[2])
		wOut[2], wOut[6] = vOutR, vOutI

		vOutR = wOut[3] + (w0[3]*w1[3] - w0[7]*w1[7])
		vOutI = wOut[7] + (w0[3]*w1[7] + w0[7]*w1[3])
		wOut[3], wOut[7] = vOutR, vOutI
	}
}

// mulSubCmplxTo computes vOut -= v0 * v1.
func mulSubCmplxTo(vOut, v0, v1 []float64) {
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	var vOutR, vOutI float64
	for i := 0; i < len(vOut); i += 8 {
		wOut := (*[8]float64)(unsafe.Pointer(uintptr(ptrOut) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w0 := (*[8]float64)(unsafe.Pointer(uintptr(ptr0) + uintptr(i)*unsafe.Sizeof(float64(0))))
		w1 := (*[8]float64)(unsafe.Pointer(uintptr(ptr1) + uintptr(i)*unsafe.Sizeof(float64(0))))

		vOutR = wOut[0] - (w0[0]*w1[0] - w0[4]*w1[4])
		vOutI = wOut[4] - (w0[0]*w1[4] + w0[4]*w1[0])
		wOut[0], wOut[4] = vOutR, vOutI

		vOutR = wOut[1] - (w0[1]*w1[1] - w0[5]*w1[5])
		vOutI = wOut[5] - (w0[1]*w1[5] + w0[5]*w1[1])
		wOut[1], wOut[5] = vOutR, vOutI

		vOutR = wOut[2] - (w0[2]*w1[2] - w0[6]*w1[6])
		vOutI = wOut[6] - (w0[2]*w1[6] + w0[6]*w1[2])
		wOut[2], wOut[6] = vOutR, vOutI

		vOutR = wOut[3] - (w0[3]*w1[3] - w0[7]*w1[7])
		vOutI = wOut[7] - (w0[3]*w1[7] + w0[7]*w1[3])
		wOut[3], wOut[7] = vOutR, vOutI
	}
}
