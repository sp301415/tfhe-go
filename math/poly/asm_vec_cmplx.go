//go:build !(amd64 && !purego)

package poly

import (
	"math"
)

// roundCmplxAssign computes vOut = round(v0).
func roundCmplxAssign(v0, vOut []float64) {
	for i := range vOut {
		vOut[i] = math.Round(v0[i])
	}
}

// addCmplxAssign computes vOut = v0 + v1.
func addCmplxAssign(v0, v1, vOut []float64) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// subCmplxAssign computes vOut = v0 - v1.
func subCmplxAssign(v0, v1, vOut []float64) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// negCmplxAssign computes vOut = -v0.
func negCmplxAssign(v0, vOut []float64) {
	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

// floatMulCmplxAssign computes vOut = c * v0.
func floatMulCmplxAssign(v0 []float64, c float64, vOut []float64) {
	for i := range vOut {
		vOut[i] = c * v0[i]
	}
}

// elementWiseMulCmplxAssign computes vOut = v0 * v1.
func elementWiseMulCmplxAssign(v0, v1, vOut []float64) {
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

// elementWiseMulAddCmplxAssign computes vOut += v0 * v1.
func elementWiseMulAddCmplxAssign(v0, v1, vOut []float64) {
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

// elementWiseMulSubCmplxAssign computes vOut -= v0 * v1.
func elementWiseMulSubCmplxAssign(v0, v1, vOut []float64) {
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
