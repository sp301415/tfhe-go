//go:build amd64 && !purego

package poly

import (
	"math"

	"golang.org/x/sys/cpu"
)

func roundCmplxAssignAVX2(v0, vOut []float64)

// roundCmplxAssign computes vOut = round(v0).
func roundCmplxAssign(v0, vOut []float64) {
	if cpu.X86.HasAVX2 {
		roundCmplxAssignAVX2(v0, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = math.Round(v0[i])
	}
}

func addCmplxAssignAVX2(v0, v1, vOut []float64)

// addCmplxAssign computes vOut = v0 + v1.
func addCmplxAssign(v0, v1, vOut []float64) {
	if cpu.X86.HasAVX2 {
		addCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

func subCmplxAssignAVX2(v0, v1, vOut []float64)

// subCmplxAssign computes vOut = v0 - v1.
func subCmplxAssign(v0, v1, vOut []float64) {
	if cpu.X86.HasAVX2 {
		subCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

func negCmplxAssignAVX2(v0, vOut []float64)

// negCmplxAssign computes vOut = -v0.
func negCmplxAssign(v0, vOut []float64) {
	if cpu.X86.HasAVX2 {
		negCmplxAssignAVX2(v0, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

func floatMulCmplxAssignAVX2(v0 []float64, c float64, vOut []float64)

// floatMulCmplxAssign computes vOut = c * v0.
func floatMulCmplxAssign(v0 []float64, c float64, vOut []float64) {
	if cpu.X86.HasAVX2 {
		floatMulCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

func elementWiseMulCmplxAssignAVX2(v0, v1, vOut []float64)

// elementWiseMulCmplxAssign computes vOut = v0 * v1.
func elementWiseMulCmplxAssign(v0, v1, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		elementWiseMulCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		vOut0 := v0[i+0]*v1[i+0] - v0[i+4]*v1[i+4]
		vOut1 := v0[i+1]*v1[i+1] - v0[i+5]*v1[i+5]
		vOut2 := v0[i+2]*v1[i+2] - v0[i+6]*v1[i+6]
		vOut3 := v0[i+3]*v1[i+3] - v0[i+7]*v1[i+7]

		vOut4 := v0[i+0]*v1[i+4] + v0[i+4]*v1[i+0]
		vOut5 := v0[i+1]*v1[i+5] + v0[i+5]*v1[i+1]
		vOut6 := v0[i+2]*v1[i+6] + v0[i+6]*v1[i+2]
		vOut7 := v0[i+3]*v1[i+7] + v0[i+7]*v1[i+3]

		vOut[i+0] = vOut0
		vOut[i+1] = vOut1
		vOut[i+2] = vOut2
		vOut[i+3] = vOut3

		vOut[i+4] = vOut4
		vOut[i+5] = vOut5
		vOut[i+6] = vOut6
		vOut[i+7] = vOut7
	}
}

func elementWiseMulAddCmplxAssignAVX2(v0, v1, vOut []float64)

// elementWiseMulAddCmplxAssign computes vOut += v0 * v1.
func elementWiseMulAddCmplxAssign(v0, v1, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		elementWiseMulAddCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		vOut0 := vOut[i+0] + (v0[i+0]*v1[i+0] - v0[i+4]*v1[i+4])
		vOut1 := vOut[i+1] + (v0[i+1]*v1[i+1] - v0[i+5]*v1[i+5])
		vOut2 := vOut[i+2] + (v0[i+2]*v1[i+2] - v0[i+6]*v1[i+6])
		vOut3 := vOut[i+3] + (v0[i+3]*v1[i+3] - v0[i+7]*v1[i+7])

		vOut4 := vOut[i+4] + (v0[i+0]*v1[i+4] + v0[i+4]*v1[i+0])
		vOut5 := vOut[i+5] + (v0[i+1]*v1[i+5] + v0[i+5]*v1[i+1])
		vOut6 := vOut[i+6] + (v0[i+2]*v1[i+6] + v0[i+6]*v1[i+2])
		vOut7 := vOut[i+7] + (v0[i+3]*v1[i+7] + v0[i+7]*v1[i+3])

		vOut[i+0] = vOut0
		vOut[i+1] = vOut1
		vOut[i+2] = vOut2
		vOut[i+3] = vOut3

		vOut[i+4] = vOut4
		vOut[i+5] = vOut5
		vOut[i+6] = vOut6
		vOut[i+7] = vOut7
	}
}

func elementWiseMulSubCmplxAssignAVX2(v0, v1, vOut []float64)

// elementWiseMulSubCmplxAssign computes vOut -= v0 * v1.
func elementWiseMulSubCmplxAssign(v0, v1, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		elementWiseMulSubCmplxAssignAVX2(v0, v1, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		vOut0 := vOut[i+0] - (v0[i+0]*v1[i+0] - v0[i+4]*v1[i+4])
		vOut1 := vOut[i+1] - (v0[i+1]*v1[i+1] - v0[i+5]*v1[i+5])
		vOut2 := vOut[i+2] - (v0[i+2]*v1[i+2] - v0[i+6]*v1[i+6])
		vOut3 := vOut[i+3] - (v0[i+3]*v1[i+3] - v0[i+7]*v1[i+7])

		vOut4 := vOut[i+4] - (v0[i+0]*v1[i+4] + v0[i+4]*v1[i+0])
		vOut5 := vOut[i+5] - (v0[i+1]*v1[i+5] + v0[i+5]*v1[i+1])
		vOut6 := vOut[i+6] - (v0[i+2]*v1[i+6] + v0[i+6]*v1[i+2])
		vOut7 := vOut[i+7] - (v0[i+3]*v1[i+7] + v0[i+7]*v1[i+3])

		vOut[i+0] = vOut0
		vOut[i+1] = vOut1
		vOut[i+2] = vOut2
		vOut[i+3] = vOut3

		vOut[i+4] = vOut4
		vOut[i+5] = vOut5
		vOut[i+6] = vOut6
		vOut[i+7] = vOut7
	}
}
