package tfheb_test

import (
	"testing"

	"github.com/sp301415/tfhe/tfhe"
	"github.com/sp301415/tfhe/tfheb"
	"github.com/stretchr/testify/assert"
)

var (
	testParams = tfheb.ParamsBoolean.Compile()
	enc        = tfheb.NewEncrypter(testParams)
	eval       = tfheb.NewEvaluater(testParams, enc.GenEvaluationKeyParallel())
)

func TestEvaluater(t *testing.T) {
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
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := enc.EncryptLWEBool(true)
	ct1 := enc.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(testParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eval.ANDInPlace(ct0, ct1, ctOut)
	}
}
