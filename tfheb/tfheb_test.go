package tfheb_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/tfheb"
	"github.com/stretchr/testify/assert"
)

var (
	testParams = tfheb.ParamsBoolean.Compile()
	enc        = tfheb.NewEncryptor(testParams)
	eval       = tfheb.NewEvaluator(testParams, enc.GenEvaluationKeyParallel())
)

func TestEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 tfhe.LWECiphertext[uint32]
		ct1 tfhe.LWECiphertext[uint32]
	}{
		{true, true, enc.EncryptLWEBool(true), enc.EncryptLWEBool(true)},
		{true, false, enc.EncryptLWEBool(true), enc.EncryptLWEBool(false)},
		{false, true, enc.EncryptLWEBool(false), enc.EncryptLWEBool(true)},
		{false, false, enc.EncryptLWEBool(false), enc.EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, enc.DecryptLWEBool(eval.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), enc.DecryptLWEBool(eval.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, enc.DecryptLWEBool(eval.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), enc.DecryptLWEBool(eval.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, enc.DecryptLWEBool(eval.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, enc.DecryptLWEBool(eval.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := enc.EncryptLWEBits(msg0)[:4]
		ct1 := enc.EncryptLWEBits(msg1)[:4]

		ctOut := enc.EncryptLWEBits(0)[:4]
		for i := range ctOut {
			eval.XORAssign(ct0[i], ct1[i], ctOut[i])
		}

		assert.Equal(t, enc.DecryptLWEBits(ctOut), msg0^msg1)
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := enc.EncryptLWEBool(true)
	ct1 := enc.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(testParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eval.ANDAssign(ct0, ct1, ctOut)
	}
}
