package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testBinaryParams    = tfhe.ParamsBinary.Compile()
	testBinaryEncryptor = tfhe.NewBinaryEncryptor(testBinaryParams)
	testBinaryEvaluator = tfhe.NewBinaryEvaluator(testBinaryParams, testBinaryEncryptor.GenEvaluationKeyParallel())
)

func TestBinaryParams(t *testing.T) {
	t.Run("ParamsBinary", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinary.Compile() })
	})
}

func TestBinaryEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 tfhe.LWECiphertext[uint32]
		ct1 tfhe.LWECiphertext[uint32]
	}{
		{true, true, testBinaryEncryptor.EncryptLWEBool(true), testBinaryEncryptor.EncryptLWEBool(true)},
		{true, false, testBinaryEncryptor.EncryptLWEBool(true), testBinaryEncryptor.EncryptLWEBool(false)},
		{false, true, testBinaryEncryptor.EncryptLWEBool(false), testBinaryEncryptor.EncryptLWEBool(true)},
		{false, false, testBinaryEncryptor.EncryptLWEBool(false), testBinaryEncryptor.EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, testBinaryEncryptor.DecryptLWEBool(testBinaryEvaluator.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := testBinaryEncryptor.EncryptLWEBits(msg0, 4)
		ct1 := testBinaryEncryptor.EncryptLWEBits(msg1, 4)

		ctOut := testBinaryEncryptor.EncryptLWEBits(0, 4)
		for i := range ctOut {
			testBinaryEvaluator.XORAssign(ct0[i], ct1[i], ctOut[i])
		}

		assert.Equal(t, testBinaryEncryptor.DecryptLWEBits(ctOut), msg0^msg1)
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := testBinaryEncryptor.EncryptLWEBool(true)
	ct1 := testBinaryEncryptor.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(testBinaryParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		testBinaryEvaluator.ANDAssign(ct0, ct1, ctOut)
	}
}
