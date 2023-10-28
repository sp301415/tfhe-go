//go:build amd64

package asm

import (
	"golang.org/x/sys/cpu"
)

func addCmplxAssignAVX2(v0, v1, vOut []complex128)

// AddCmplxAssign adds v0, v1 and writes it to vOut.
func AddCmplxAssign(v0, v1, vOut []complex128) {
	if cpu.X86.HasAVX2 {
		addCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

func subCmplxAssignAVX2(v0, v1, vOut []complex128)

// SubCmplxAssign subtracts v0, v1 and writes it to vOut.
func SubCmplxAssign(v0, v1, vOut []complex128) {
	if cpu.X86.HasAVX2 {
		subCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

func negCmplxAssignAVX2(v0, vOut []complex128)

// NegCmplxAssign negates v0 and writes it to vOut.
func NegCmplxAssign(v0, vOut []complex128) {
	if cpu.X86.HasAVX2 {
		negCmplxAssignAVX2(v0, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

func elementWiseMulCmplxAssignAVX2(v0, v1, vOut []complex128)

// ElementWiseMulCmplxAssign multiplies v0, v1 and writes it to vOut.
func ElementWiseMulCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	if cpu.X86.HasFMA && cpu.X86.HasAVX2 {
		elementWiseMulCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

func elementWiseMulAddCmplxAssignAVX2(v0, v1, vOut []complex128)

// ElementWiseMulAddCmplxAssign multiplies v0, v1 and adds to vOut.
func ElementWiseMulAddCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	if cpu.X86.HasFMA && cpu.X86.HasAVX2 {
		elementWiseMulAddCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

func elementWiseMulSubCmplxAssignAVX2(v0, v1, vOut []complex128)

// ElementWiseMulSubCmplxAssign multiplies v0, v1 and subtracts from vOut.
func ElementWiseMulSubCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	if cpu.X86.HasFMA && cpu.X86.HasAVX2 {
		elementWiseMulSubCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
