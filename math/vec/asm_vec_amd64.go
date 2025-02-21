//go:build amd64 && !purego

package vec

import (
	"unsafe"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/sys/cpu"
)

// AddAssign computes vOut = v0 + v1.
func AddAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			addAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			addAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// SubAssign computes vOut = v0 - v1.
func SubAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			subAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			subAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// ScalarMulAssign computes vOut = c * v0.
func ScalarMulAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

// ScalarMulAddAssign computes vOut += c * v0.
func ScalarMulAddAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] += c * v0[i]
	}
}

// ScalarMulSubAssign computes vOut -= c * v0.
func ScalarMulSubAssign[T num.Number](v0 []T, c T, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			scalarMulSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*uint32)(unsafe.Pointer(&c)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			scalarMulSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*uint64)(unsafe.Pointer(&c)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] -= c * v0[i]
	}
}

// ElementWiseMulAssign computes vOut = v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAddAssign computes vOut += v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulAddAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulAddAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulAddAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubAssign computes vOut -= v0 * v1, where * is an elementwise multiplication.
func ElementWiseMulSubAssign[T num.Number](v0, v1, vOut []T) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		var z T
		switch any(z).(type) {
		case uint32:
			elementWiseMulSubAssignUint32AVX2(
				*(*[]uint32)(unsafe.Pointer(&v0)),
				*(*[]uint32)(unsafe.Pointer(&v1)),
				*(*[]uint32)(unsafe.Pointer(&vOut)),
			)
			return

		case uint64:
			elementWiseMulSubAssignUint64AVX2(
				*(*[]uint64)(unsafe.Pointer(&v0)),
				*(*[]uint64)(unsafe.Pointer(&v1)),
				*(*[]uint64)(unsafe.Pointer(&vOut)),
			)
			return
		}
	}

	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
