package tfhe_test

import (
	"fmt"
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	paramsBinary = tfhe.ParamsBinary.Compile()
	encBinary    = tfhe.NewBinaryEncryptor(paramsBinary)
	evalBinary   = tfhe.NewBinaryEvaluator(paramsBinary, encBinary.GenEvaluationKeyParallel())
)

func TestBinaryParams(t *testing.T) {
	t.Run("ParamsBinary", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinary.Compile() })
	})

	t.Run("ParamsBinaryCompact", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinaryCompact.Compile() })
	})

	t.Run("ParamsBinaryOriginal", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinaryOriginal.Compile() })
	})
}

func TestBinaryEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 tfhe.LWECiphertext[uint32]
		ct1 tfhe.LWECiphertext[uint32]
	}{
		{true, true, encBinary.EncryptLWEBool(true), encBinary.EncryptLWEBool(true)},
		{true, false, encBinary.EncryptLWEBool(true), encBinary.EncryptLWEBool(false)},
		{false, true, encBinary.EncryptLWEBool(false), encBinary.EncryptLWEBool(true)},
		{false, false, encBinary.EncryptLWEBool(false), encBinary.EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, encBinary.DecryptLWEBool(evalBinary.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), encBinary.DecryptLWEBool(evalBinary.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, encBinary.DecryptLWEBool(evalBinary.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), encBinary.DecryptLWEBool(evalBinary.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, encBinary.DecryptLWEBool(evalBinary.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, encBinary.DecryptLWEBool(evalBinary.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := encBinary.EncryptLWEBits(msg0, 4)
		ct1 := encBinary.EncryptLWEBits(msg1, 4)

		ctOut := encBinary.EncryptLWEBits(0, 4)
		for i := range ctOut {
			evalBinary.XORAssign(ct0[i], ct1[i], ctOut[i])
		}

		assert.Equal(t, encBinary.DecryptLWEBits(ctOut), msg0^msg1)
	})

	t.Run("BootstrapOriginal", func(t *testing.T) {
		paramsBinaryOriginal := paramsBinary.Literal().WithBlockSize(1).Compile()

		originalEncryptor := tfhe.NewBinaryEncryptorWithKey(paramsBinaryOriginal, encBinary.BaseEncryptor.SecretKey)
		originalEvaluator := tfhe.NewBinaryEvaluator(paramsBinaryOriginal, evalBinary.BaseEvaluator.EvaluationKey)

		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, originalEncryptor.DecryptLWEBool(originalEvaluator.AND(tc.ct0, tc.ct1)))
		}
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := encBinary.EncryptLWEBool(true)
	ct1 := encBinary.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(paramsBinary)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		evalBinary.ANDAssign(ct0, ct1, ctOut)
	}
}

func ExampleBinaryEvaluator() {
	params := tfhe.ParamsBinary.Compile()

	enc := tfhe.NewBinaryEncryptor(params)

	bits := 16
	ct0 := enc.EncryptLWEBits(3, bits)
	ct1 := enc.EncryptLWEBits(3, bits)

	eval := tfhe.NewBinaryEvaluator(params, enc.GenEvaluationKeyParallel())

	ctXNOR := tfhe.NewLWECiphertext(params)
	ctOut := eval.XNOR(ct0[0], ct1[0])
	for i := 1; i < bits; i++ {
		eval.XNORAssign(ct0[i], ct1[i], ctXNOR)
		eval.ANDAssign(ctXNOR, ctOut, ctOut)
	}

	fmt.Println(enc.DecryptLWEBool(ctOut))
	// Output:
	// true
}
