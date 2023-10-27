//go:build !amd64

package vec

// AddCmplx adds v0, v1 and returns the result.
func AddCmplx(v0, v1 []complex128) []complex128 {
	v := make([]complex128, len(v0))
	AddCmplxAssign(v0, v1, v)
	return v
}

// AddCmplxAssign adds v0, v1 and writes it to vOut.
func AddCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] + v1[i]
	}
}

// SubCmplx subtracts v0, v1 and returns the result.
func SubCmplx(v0, v1 []complex128) []complex128 {
	v := make([]complex128, len(v0))
	SubCmplxAssign(v0, v1, v)
	return v
}

// SubCmplxAssign subtracts v0, v1 and writes it to vOut.
func SubCmplxAssign(v0, v1, vOut []complex128) {
	for i := range vOut {
		vOut[i] = v0[i] - v1[i]
	}
}

// NegCmplx negates v0 and returns the result.
func NegCmplx(v0 []complex128) []complex128 {
	v := make([]complex128, len(v0))
	NegCmplxAssign(v0, v)
	return v
}

// NegCmplxAssign negates v0 and writes it to vOut.
func NegCmplxAssign(v0, vOut []complex128) {
	for i := range vOut {
		vOut[i] = -v0[i]
	}
}

// ElementWiseMuCmplxl multiplies v0, v1 and returns the result.
func ElementWiseMulCmplx(v0 []complex128, v1 []complex128) []complex128 {
	v := make([]complex128, len(v0))
	ElementWiseMulCmplxAssign(v0, v1, v)
	return v
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
