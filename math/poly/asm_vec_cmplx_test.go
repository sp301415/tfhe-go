package poly

import (
	"math/cmplx"
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
)

func TestVecCmplxAssembly(t *testing.T) {
	N := 1 << 10
	eps := 1e-10

	v0 := make([]complex128, N)
	v1 := make([]complex128, N)
	for i := 0; i < N; i++ {
		v0[i] = complex(rand.Float64(), rand.Float64())
		v1[i] = complex(rand.Float64(), rand.Float64())
	}
	v0Float4 := vec.CmplxToFloat4(v0)
	v1Float4 := vec.CmplxToFloat4(v1)

	vOut := make([]complex128, N)
	vOutAVX2 := make([]complex128, N)
	vOutAVX2Float4 := make([]float64, 2*N)

	t.Run("Add", func(t *testing.T) {
		vec.AddAssign(v0, v1, vOut)
		addCmplxAssign(v0Float4, v1Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("Add: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Sub", func(t *testing.T) {
		vec.SubAssign(v0, v1, vOut)
		subCmplxAssign(v0Float4, v1Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("Sub: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Neg", func(t *testing.T) {
		vec.NegAssign(v0, vOut)
		negCmplxAssign(v0Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("Neg: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("Mul", func(t *testing.T) {
		vec.ElementWiseMulAssign(v0, v1, vOut)
		elementWiseMulCmplxAssign(v0Float4, v1Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("Mul: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("MulAdd", func(t *testing.T) {
		vec.Fill(vOut, 0)
		vec.Fill(vOutAVX2Float4, 0)

		vec.ElementWiseMulAddAssign(v0, v1, vOut)
		elementWiseMulAddCmplxAssign(v0Float4, v1Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("MulAdd: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})

	t.Run("MulSub", func(t *testing.T) {
		vec.Fill(vOut, 0)
		vec.Fill(vOutAVX2Float4, 0)

		vec.ElementWiseMulSubAssign(v0, v1, vOut)
		elementWiseMulSubCmplxAssign(v0Float4, v1Float4, vOutAVX2Float4)
		vec.Float4ToCmplxAssign(vOutAVX2Float4, vOutAVX2)
		for i := 0; i < N; i++ {
			if cmplx.Abs(vOut[i]-vOutAVX2[i]) > eps {
				t.Fatalf("MulSub: %v != %v", vOut[i], vOutAVX2[i])
			}
		}
	})
}

func BenchmarkVecCmplxAssembly(b *testing.B) {
	N := 1 << 15

	v0 := make([]complex128, N)
	v1 := make([]complex128, N)
	for i := 0; i < N; i++ {
		v0[i] = complex(rand.NormFloat64(), rand.NormFloat64())
		v1[i] = complex(rand.NormFloat64(), rand.NormFloat64())
	}
	v0Float4 := vec.CmplxToFloat4(v0)
	v1Float4 := vec.CmplxToFloat4(v1)

	vOut := make([]complex128, N)
	vOutFloat4 := make([]float64, 2*N)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.AddAssign(v0, v1, vOut)
		}
	})

	b.Run("AddAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			addCmplxAssign(v0Float4, v1Float4, vOutFloat4)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.ElementWiseMulAssign(v0, v1, vOut)
		}
	})

	b.Run("MulAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			elementWiseMulCmplxAssign(v0Float4, v1Float4, vOutFloat4)
		}
	})

	b.Run("MulAdd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			vec.ElementWiseMulAddAssign(v0, v1, vOut)
		}
	})

	b.Run("MulAddAVX2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			elementWiseMulAddCmplxAssign(v0Float4, v1Float4, vOutFloat4)
		}
	})
}
