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
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		floatMulCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

func floatMulAddCmplxAssignAVX2(v0 []float64, c float64, vOut []float64)

// floatMulAddCmplxAssign computes vOut += c * v0.
func floatMulAddCmplxAssign(v0 []float64, c float64, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		floatMulAddCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := range vOut {
		vOut[i] += c * v0[i]
	}
}

func floatMulSubCmplxAssignAVX2(v0 []float64, c float64, vOut []float64)

// floatMulSubCmplxAssign computes vOut -= c * v0.
func floatMulSubCmplxAssign(v0 []float64, c float64, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		floatMulSubCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := range vOut {
		vOut[i] -= c * v0[i]
	}
}

func cmplxMulCmplxAssignAVX2(v0 []float64, c complex128, vOut []float64)

// cmplxMulCmplxAssign computes vOut = c * v0.
func cmplxMulCmplxAssign(v0 []float64, c complex128, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		cmplxMulCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		v0Tmp := v0[i : i+8 : i+8]
		vOutTmp := vOut[i : i+8 : i+8]

		vOutTmp[0] = v0Tmp[0]*real(c) - v0Tmp[4]*imag(c)
		vOutTmp[1] = v0Tmp[1]*real(c) - v0Tmp[5]*imag(c)
		vOutTmp[2] = v0Tmp[2]*real(c) - v0Tmp[6]*imag(c)
		vOutTmp[3] = v0Tmp[3]*real(c) - v0Tmp[7]*imag(c)

		vOutTmp[4] = v0Tmp[0]*imag(c) + v0Tmp[4]*real(c)
		vOutTmp[5] = v0Tmp[1]*imag(c) + v0Tmp[5]*real(c)
		vOutTmp[6] = v0Tmp[2]*imag(c) + v0Tmp[6]*real(c)
		vOutTmp[7] = v0Tmp[3]*imag(c) + v0Tmp[7]*real(c)
	}
}

func cmplxMulAddCmplxAssignAVX2(v0 []float64, c complex128, vOut []float64)

// cmplxMulAddCmplxAssign computes vOut += c * v0.
func cmplxMulAddCmplxAssign(v0 []float64, c complex128, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		cmplxMulAddCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		v0Tmp := v0[i : i+8 : i+8]
		vOutTmp := vOut[i : i+8 : i+8]

		vOutTmp[0] += v0Tmp[0]*real(c) - v0Tmp[4]*imag(c)
		vOutTmp[1] += v0Tmp[1]*real(c) - v0Tmp[5]*imag(c)
		vOutTmp[2] += v0Tmp[2]*real(c) - v0Tmp[6]*imag(c)
		vOutTmp[3] += v0Tmp[3]*real(c) - v0Tmp[7]*imag(c)

		vOutTmp[4] += v0Tmp[0]*imag(c) + v0Tmp[4]*real(c)
		vOutTmp[5] += v0Tmp[1]*imag(c) + v0Tmp[5]*real(c)
		vOutTmp[6] += v0Tmp[2]*imag(c) + v0Tmp[6]*real(c)
		vOutTmp[7] += v0Tmp[3]*imag(c) + v0Tmp[7]*real(c)
	}
}

func cmplxMulSubCmplxAssignAVX2(v0 []float64, c complex128, vOut []float64)

// cmplxMulSubCmplxAssign computes vOut -= c * v0.
func cmplxMulSubCmplxAssign(v0 []float64, c complex128, vOut []float64) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		cmplxMulSubCmplxAssignAVX2(v0, c, vOut)
		return
	}

	for i := 0; i < len(vOut); i += 8 {
		v0Tmp := v0[i : i+8 : i+8]
		vOutTmp := vOut[i : i+8 : i+8]

		vOutTmp[0] -= v0Tmp[0]*real(c) - v0Tmp[4]*imag(c)
		vOutTmp[1] -= v0Tmp[1]*real(c) - v0Tmp[5]*imag(c)
		vOutTmp[2] -= v0Tmp[2]*real(c) - v0Tmp[6]*imag(c)
		vOutTmp[3] -= v0Tmp[3]*real(c) - v0Tmp[7]*imag(c)

		vOutTmp[4] -= v0Tmp[0]*imag(c) + v0Tmp[4]*real(c)
		vOutTmp[5] -= v0Tmp[1]*imag(c) + v0Tmp[5]*real(c)
		vOutTmp[6] -= v0Tmp[2]*imag(c) + v0Tmp[6]*real(c)
		vOutTmp[7] -= v0Tmp[3]*imag(c) + v0Tmp[7]*real(c)
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
		v0Tmp := v0[i+0 : i+8 : i+8]
		v1Tmp := v1[i+0 : i+8 : i+8]
		vOutTmp := vOut[i+0 : i+8 : i+8]

		vOut0 := v0Tmp[0]*v1Tmp[0] - v0Tmp[4]*v1Tmp[4]
		vOut1 := v0Tmp[1]*v1Tmp[1] - v0Tmp[5]*v1Tmp[5]
		vOut2 := v0Tmp[2]*v1Tmp[2] - v0Tmp[6]*v1Tmp[6]
		vOut3 := v0Tmp[3]*v1Tmp[3] - v0Tmp[7]*v1Tmp[7]

		vOut4 := v0Tmp[0]*v1Tmp[4] + v0Tmp[4]*v1Tmp[0]
		vOut5 := v0Tmp[1]*v1Tmp[5] + v0Tmp[5]*v1Tmp[1]
		vOut6 := v0Tmp[2]*v1Tmp[6] + v0Tmp[6]*v1Tmp[2]
		vOut7 := v0Tmp[3]*v1Tmp[7] + v0Tmp[7]*v1Tmp[3]

		vOutTmp[0] = vOut0
		vOutTmp[1] = vOut1
		vOutTmp[2] = vOut2
		vOutTmp[3] = vOut3

		vOutTmp[4] = vOut4
		vOutTmp[5] = vOut5
		vOutTmp[6] = vOut6
		vOutTmp[7] = vOut7
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
		v0Tmp := v0[i+0 : i+8 : i+8]
		v1Tmp := v1[i+0 : i+8 : i+8]
		vOutTmp := vOut[i+0 : i+8 : i+8]

		vOut0 := vOutTmp[0] + (v0Tmp[0]*v1Tmp[0] - v0Tmp[4]*v1Tmp[4])
		vOut1 := vOutTmp[1] + (v0Tmp[1]*v1Tmp[1] - v0Tmp[5]*v1Tmp[5])
		vOut2 := vOutTmp[2] + (v0Tmp[2]*v1Tmp[2] - v0Tmp[6]*v1Tmp[6])
		vOut3 := vOutTmp[3] + (v0Tmp[3]*v1Tmp[3] - v0Tmp[7]*v1Tmp[7])

		vOut4 := vOutTmp[4] + (v0Tmp[0]*v1Tmp[4] + v0Tmp[4]*v1Tmp[0])
		vOut5 := vOutTmp[5] + (v0Tmp[1]*v1Tmp[5] + v0Tmp[5]*v1Tmp[1])
		vOut6 := vOutTmp[6] + (v0Tmp[2]*v1Tmp[6] + v0Tmp[6]*v1Tmp[2])
		vOut7 := vOutTmp[7] + (v0Tmp[3]*v1Tmp[7] + v0Tmp[7]*v1Tmp[3])

		vOutTmp[0] = vOut0
		vOutTmp[1] = vOut1
		vOutTmp[2] = vOut2
		vOutTmp[3] = vOut3

		vOutTmp[4] = vOut4
		vOutTmp[5] = vOut5
		vOutTmp[6] = vOut6
		vOutTmp[7] = vOut7
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
		v0Tmp := v0[i+0 : i+8 : i+8]
		v1Tmp := v1[i+0 : i+8 : i+8]
		vOutTmp := vOut[i+0 : i+8 : i+8]

		vOut0 := vOutTmp[0] - (v0Tmp[0]*v1Tmp[0] - v0Tmp[4]*v1Tmp[4])
		vOut1 := vOutTmp[1] - (v0Tmp[1]*v1Tmp[1] - v0Tmp[5]*v1Tmp[5])
		vOut2 := vOutTmp[2] - (v0Tmp[2]*v1Tmp[2] - v0Tmp[6]*v1Tmp[6])
		vOut3 := vOutTmp[3] - (v0Tmp[3]*v1Tmp[3] - v0Tmp[7]*v1Tmp[7])

		vOut4 := vOutTmp[4] - (v0Tmp[0]*v1Tmp[4] + v0Tmp[4]*v1Tmp[0])
		vOut5 := vOutTmp[5] - (v0Tmp[1]*v1Tmp[5] + v0Tmp[5]*v1Tmp[1])
		vOut6 := vOutTmp[6] - (v0Tmp[2]*v1Tmp[6] + v0Tmp[6]*v1Tmp[2])
		vOut7 := vOutTmp[7] - (v0Tmp[3]*v1Tmp[7] + v0Tmp[7]*v1Tmp[3])

		vOutTmp[0] = vOut0
		vOutTmp[1] = vOut1
		vOutTmp[2] = vOut2
		vOutTmp[3] = vOut3

		vOutTmp[4] = vOut4
		vOutTmp[5] = vOut5
		vOutTmp[6] = vOut6
		vOutTmp[7] = vOut7
	}
}
