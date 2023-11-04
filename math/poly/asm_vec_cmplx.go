//go:build !(amd64 && !purego)

package poly

// addCmplxAssign adds v0, v1 and writes it to vOut.
func addCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// subCmplxAssign subtracts v0, v1 and writes it to vOut.
func subCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// negCmplxAssign negates v0 and writes it to vOut.
func negCmplxAssign(v0, vOut []complex128) {
	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

// elementWiseMulCmplxAssign multiplies v0, v1 and writes it to vOut.
func elementWiseMulCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] * v1[i]
	}
}

// elementWiseMulAddCmplxAssign multiplies v0, v1 and adds to vOut.
func elementWiseMulAddCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] += v0[i] * v1[i]
	}
}

// elementWiseMulSubCmplxAssign multiplies v0, v1 and subtracts from vOut.
func elementWiseMulSubCmplxAssign(v0 []complex128, v1 []complex128, vOut []complex128) {
	for i := range vOut {
		vOut[i] -= v0[i] * v1[i]
	}
}
