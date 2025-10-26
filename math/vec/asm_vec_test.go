package vec_test

import (
	"math/rand"
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/stretchr/testify/assert"
)

func TestVec(t *testing.T) {
	r := rand.New(rand.NewSource(0))

	N := 687

	v0 := make([]uint32, N)
	v1 := make([]uint32, N)
	vOut := make([]uint32, N)
	vOutAVX := make([]uint32, N)

	for i := 0; i < N; i++ {
		v0[i] = r.Uint32()
		v1[i] = r.Uint32()
	}

	w0 := make([]uint64, N)
	w1 := make([]uint64, N)
	wOut := make([]uint64, N)
	wOutAVX := make([]uint64, N)

	for i := 0; i < N; i++ {
		w0[i] = r.Uint64()
		w1[i] = r.Uint64()
	}

	t.Run("AddTo", func(t *testing.T) {
		for i := 0; i < N; i++ {
			vOut[i] = v0[i] + v1[i]
			wOut[i] = w0[i] + w1[i]
		}
		vec.AddTo(vOutAVX, v0, v1)
		vec.AddTo(wOutAVX, w0, w1)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("SubTo", func(t *testing.T) {
		for i := 0; i < N; i++ {
			vOut[i] = v0[i] - v1[i]
			wOut[i] = w0[i] - w1[i]
		}
		vec.SubTo(vOutAVX, v0, v1)
		vec.SubTo(wOutAVX, w0, w1)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("ScalarMulTo", func(t *testing.T) {
		cv := vOut[0]
		cw := wOut[0]
		for i := 0; i < N; i++ {
			vOut[i] = cv * v0[i]
			wOut[i] = cw * w0[i]
		}
		vec.ScalarMulTo(vOutAVX, v0, cv)
		vec.ScalarMulTo(wOutAVX, w0, cw)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("ScalarMulAddTo", func(t *testing.T) {
		cv := vOut[0]
		cw := wOut[0]
		for i := 0; i < N; i++ {
			vOut[i] += cv * v0[i]
			wOut[i] += cw * w0[i]
		}
		vec.ScalarMulAddTo(vOutAVX, v0, cv)
		vec.ScalarMulAddTo(wOutAVX, w0, cw)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("ScalarMulSubTo", func(t *testing.T) {
		cv := vOut[0]
		cw := wOut[0]
		for i := 0; i < N; i++ {
			vOut[i] -= cv * v0[i]
			wOut[i] -= cw * w0[i]
		}
		vec.ScalarMulSubTo(vOutAVX, v0, cv)
		vec.ScalarMulSubTo(wOutAVX, w0, cw)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("MulTo", func(t *testing.T) {
		for i := 0; i < N; i++ {
			vOut[i] = v0[i] * v1[i]
			wOut[i] = w0[i] * w1[i]
		}
		vec.MulTo(vOutAVX, v0, v1)
		vec.MulTo(wOutAVX, w0, w1)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("MulAddTo", func(t *testing.T) {
		for i := 0; i < N; i++ {
			vOut[i] += v0[i] * v1[i]
			wOut[i] += w0[i] * w1[i]
		}
		vec.MulAddTo(vOutAVX, v0, v1)
		vec.MulAddTo(wOutAVX, w0, w1)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})

	t.Run("MulSubTo", func(t *testing.T) {
		for i := 0; i < N; i++ {
			vOut[i] -= v0[i] * v1[i]
			wOut[i] -= w0[i] * w1[i]
		}
		vec.MulSubTo(vOutAVX, v0, v1)
		vec.MulSubTo(wOutAVX, w0, w1)

		assert.Equal(t, vOut, vOutAVX)
		assert.Equal(t, wOut, wOutAVX)
	})
}
