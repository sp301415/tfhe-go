//go:build !amd64

package asm

// AddCmplxAssign adds v0, v1 and writes it to vOut.
func AddCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// CmplxAssign subtracts v0, v1 and writes it to vOut.
func SubCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// NegCmplxAssign negates v0 and writes it to vOut.
func NegCmplxAssign(v0, vOut []complex128) {
	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

// ElementWiseMulCmplxAssign multiplies v0, v1 and writes it to vOut.
func ElementWiseMulCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

// ElementWiseMulAddCmplxAssign multiplies v0, v1 and adds to vOut.
func ElementWiseMulAddCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

// ElementWiseMulSubCmplxAssign multiplies v0, v1 and subtracts from vOut.
func ElementWiseMulSubCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
