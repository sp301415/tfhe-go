package asm_test

import (
	"math/cmplx"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/poly/internal/asm"
	"github.com/sp301415/tfhe-go/math/vec"
)

func TestCmplx(t *testing.T) {
	N := 1 << 4
	eps := 1e-10

	v0 := make([]complex128, N)
	v1 := make([]complex128, N)
	for i := 0; i < N; i++ {
		v0[i] = complex(rand.NormFloat64(), rand.NormFloat64())
		v1[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}

	vOut := make([]complex128, N)
	vOutAVX2 := make([]complex128, N)

	t.Run("Add", func(t *testing.T) {
		vec.AddAssign(v0, v1, vOut)
		asm.AddCmplxAssign(v0, v1, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("Add: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Sub", func(t *testing.T) {
		vec.SubAssign(v0, v1, vOut)
		asm.SubCmplxAssign(v0, v1, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("Sub: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Neg", func(t *testing.T) {
		vec.NegAssign(v0, vOut)
		asm.NegCmplxAssign(v0, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("Neg: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Mul", func(t *testing.T) {
		vec.ElementWiseMulAssign(v0, v1, vOut)
		asm.ElementWiseMulCmplxAssign(v0, v1, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("Mul: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("MulAdd", func(t *testing.T) {
		copy(vOut, vOutAVX2)
		vec.ElementWiseMulAddAssign(v0, v1, vOut)
		asm.ElementWiseMulAddCmplxAssign(v0, v1, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("MulAdd: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("MulSub", func(t *testing.T) {
		copy(vOut, vOutAVX2)
		vec.ElementWiseMulSubAssign(v0, v1, vOut)
		asm.ElementWiseMulSubCmplxAssign(v0, v1, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Errorf("MulSub: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})
}

func BenchmarkCmplx(b *testing.B) {
	N := 1 << 10

	v0 := make([]complex128, N)
	v1 := make([]complex128, N)
	for i := 0; i < N; i++ {
		v0[i] = complex(rand.NormFloat64(), rand.NormFloat64())
		v1[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}

	vOut := make([]complex128, N)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.AddAssign(v0, v1, vOut)
		}
	})

	b.Run("AddAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			asm.AddCmplxAssign(v0, v1, vOut)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.ElementWiseMulAssign(v0, v1, vOut)
		}
	})

	b.Run("MulAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			asm.ElementWiseMulCmplxAssign(v0, v1, vOut)
		}
	})

	b.Run("MulAdd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.ElementWiseMulAddAssign(v0, v1, vOut)
		}
	})

	b.Run("MulAddAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			asm.ElementWiseMulAddCmplxAssign(v0, v1, vOut)
		}
	})
}
