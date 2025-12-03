//go:build amd64 && !purego

package vec

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

// AddTo computes vOut = v0 + v1.
func AddTo[T num.Number](vOut, v0, v1 []T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			addToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
			)
			return

		case uint64:
			addToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w0 := (*[8]T)(unsafe.Add(ptr0, uintptr(i)*unsafe.Sizeof(T(0))))
		w1 := (*[8]T)(unsafe.Add(ptr1, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] = w0[0] + w1[0]
		wOut[1] = w0[1] + w1[1]
		wOut[2] = w0[2] + w1[2]
		wOut[3] = w0[3] + w1[3]

		wOut[4] = w0[4] + w1[4]
		wOut[5] = w0[5] + w1[5]
		wOut[6] = w0[6] + w1[6]
		wOut[7] = w0[7] + w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] + v1[i]
	}
}

// SubTo computes vOut = v0 - v1.
func SubTo[T num.Number](vOut, v0, v1 []T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			subToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
			)
			return

		case uint64:
			subToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w0 := (*[8]T)(unsafe.Add(ptr0, uintptr(i)*unsafe.Sizeof(T(0))))
		w1 := (*[8]T)(unsafe.Add(ptr1, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] = w0[0] - w1[0]
		wOut[1] = w0[1] - w1[1]
		wOut[2] = w0[2] - w1[2]
		wOut[3] = w0[3] - w1[3]

		wOut[4] = w0[4] - w1[4]
		wOut[5] = w0[5] - w1[5]
		wOut[6] = w0[6] - w1[6]
		wOut[7] = w0[7] - w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] - v1[i]
	}
}

// ScalarMulTo computes vOut = c * v.
func ScalarMulTo[T num.Number](vOut, v []T, c T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v)),
				*(*uint32)(unsafe.Pointer(&c)),
			)
			return

		case uint64:
			scalarMulToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v)),
				*(*uint64)(unsafe.Pointer(&c)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w := (*[8]T)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] = c * w[0]
		wOut[1] = c * w[1]
		wOut[2] = c * w[2]
		wOut[3] = c * w[3]

		wOut[4] = c * w[4]
		wOut[5] = c * w[5]
		wOut[6] = c * w[6]
		wOut[7] = c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = c * v[i]
	}
}

// ScalarMulAddTo computes vOut += c * v.
func ScalarMulAddTo[T num.Number](vOut, v []T, c T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulAddToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v)),
				*(*uint32)(unsafe.Pointer(&c)),
			)
			return

		case uint64:
			scalarMulAddToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v)),
				*(*uint64)(unsafe.Pointer(&c)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w := (*[8]T)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] += c * w[0]
		wOut[1] += c * w[1]
		wOut[2] += c * w[2]
		wOut[3] += c * w[3]

		wOut[4] += c * w[4]
		wOut[5] += c * w[5]
		wOut[6] += c * w[6]
		wOut[7] += c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] += c * v[i]
	}
}

// ScalarMulSubTo computes vOut -= c * v0.
func ScalarMulSubTo[T num.Number](vOut, v []T, c T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulSubToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v)),
				*(*uint32)(unsafe.Pointer(&c)),
			)
			return

		case uint64:
			scalarMulSubToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v)),
				*(*uint64)(unsafe.Pointer(&c)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr := unsafe.Pointer(&v[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w := (*[8]T)(unsafe.Add(ptr, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] -= c * w[0]
		wOut[1] -= c * w[1]
		wOut[2] -= c * w[2]
		wOut[3] -= c * w[3]

		wOut[4] -= c * w[4]
		wOut[5] -= c * w[5]
		wOut[6] -= c * w[6]
		wOut[7] -= c * w[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] -= c * v[i]
	}
}

// MulTo computes vOut = v0 * v1, where * is an elementwise multiplication.
func MulTo[T num.Number](vOut, v0, v1 []T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			mulToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
			)
			return

		case uint64:
			mulToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w0 := (*[8]T)(unsafe.Add(ptr0, uintptr(i)*unsafe.Sizeof(T(0))))
		w1 := (*[8]T)(unsafe.Add(ptr1, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] = w0[0] * w1[0]
		wOut[1] = w0[1] * w1[1]
		wOut[2] = w0[2] * w1[2]
		wOut[3] = w0[3] * w1[3]

		wOut[4] = w0[4] * w1[4]
		wOut[5] = w0[5] * w1[5]
		wOut[6] = w0[6] * w1[6]
		wOut[7] = w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] = v0[i] * v1[i]
	}
}

// MulAddTo computes vOut += v0 * v1, where * is an elementwise multiplication.
func MulAddTo[T num.Number](vOut, v0, v1 []T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			mulAddToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
			)
			return

		case uint64:
			mulAddToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w0 := (*[8]T)(unsafe.Add(ptr0, uintptr(i)*unsafe.Sizeof(T(0))))
		w1 := (*[8]T)(unsafe.Add(ptr1, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] += w0[0] * w1[0]
		wOut[1] += w0[1] * w1[1]
		wOut[2] += w0[2] * w1[2]
		wOut[3] += w0[3] * w1[3]

		wOut[4] += w0[4] * w1[4]
		wOut[5] += w0[5] * w1[5]
		wOut[6] += w0[6] * w1[6]
		wOut[7] += w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] += v0[i] * v1[i]
	}
}

// MulSubTo computes vOut -= v0 * v1, where * is an elementwise multiplication.
func MulSubTo[T num.Number](vOut, v0, v1 []T) {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 {
		var z T
		switch any(z).(type) {
		case uint32:
			mulSubToUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&vOut)),
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
			)
			return

		case uint64:
			mulSubToUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&vOut)),
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
			)
			return
		}
	}

	M := (len(vOut) >> 3) << 3
	ptrOut := unsafe.Pointer(&vOut[0])
	ptr0 := unsafe.Pointer(&v0[0])
	ptr1 := unsafe.Pointer(&v1[0])

	for i := 0; i < M; i += 8 {
		wOut := (*[8]T)(unsafe.Add(ptrOut, uintptr(i)*unsafe.Sizeof(T(0))))
		w0 := (*[8]T)(unsafe.Add(ptr0, uintptr(i)*unsafe.Sizeof(T(0))))
		w1 := (*[8]T)(unsafe.Add(ptr1, uintptr(i)*unsafe.Sizeof(T(0))))

		wOut[0] -= w0[0] * w1[0]
		wOut[1] -= w0[1] * w1[1]
		wOut[2] -= w0[2] * w1[2]
		wOut[3] -= w0[3] * w1[3]

		wOut[4] -= w0[4] * w1[4]
		wOut[5] -= w0[5] * w1[5]
		wOut[6] -= w0[6] * w1[6]
		wOut[7] -= w0[7] * w1[7]
	}

	for i := M; i < len(vOut); i++ {
		vOut[i] -= v0[i] * v1[i]
	}
}
