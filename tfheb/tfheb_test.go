package tfheb_test

import (
	"bytes"
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/tfheb"
	"github.com/stretchr/testify/assert"
)

var (
	testParams    = tfheb.ParamsBoolean.Compile()
	testEncryptor = tfheb.NewEncryptor(testParams)
	testEvaluator = tfheb.NewEvaluator(testParams, testEncryptor.GenEvaluationKeyParallel())
)

func TestEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 tfhe.LWECiphertext[uint32]
		ct1 tfhe.LWECiphertext[uint32]
	}{
		{true, true, testEncryptor.EncryptLWEBool(true), testEncryptor.EncryptLWEBool(true)},
		{true, false, testEncryptor.EncryptLWEBool(true), testEncryptor.EncryptLWEBool(false)},
		{false, true, testEncryptor.EncryptLWEBool(false), testEncryptor.EncryptLWEBool(true)},
		{false, false, testEncryptor.EncryptLWEBool(false), testEncryptor.EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, testEncryptor.DecryptLWEBool(testEvaluator.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), testEncryptor.DecryptLWEBool(testEvaluator.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, testEncryptor.DecryptLWEBool(testEvaluator.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), testEncryptor.DecryptLWEBool(testEvaluator.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, testEncryptor.DecryptLWEBool(testEvaluator.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, testEncryptor.DecryptLWEBool(testEvaluator.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := testEncryptor.EncryptLWEBits(msg0, 4)
		ct1 := testEncryptor.EncryptLWEBits(msg1, 4)

		ctOut := testEncryptor.EncryptLWEBits(0, 4)
		for i := range ctOut {
			testEvaluator.XORAssign(ct0[i], ct1[i], ctOut[i])
		}

		assert.Equal(t, testEncryptor.DecryptLWEBits(ctOut), msg0^msg1)
	})
}

func TestMarshal(t *testing.T) {
	var buf bytes.Buffer
	t.Run("LWECiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.LWECiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptLWE(0)
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("LevCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.LevCiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptLev(0, testParams.KeySwitchParameters())
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GSWCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GSWCiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptGSW(0, testParams.KeySwitchParameters())
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GLWECiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptGLWE([]int{0})
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GLevCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GLevCiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptGLev([]int{0}, testParams.KeySwitchParameters())
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GGSWCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GGSWCiphertext[uint32]

		ctIn = testEncryptor.BaseEncryptor.EncryptGGSW([]int{0}, testParams.KeySwitchParameters())
		if n, err := ctIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := ctOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), ctIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("SecretKey", func(t *testing.T) {
		var skIn, skOut tfhe.SecretKey[uint32]

		skIn = testEncryptor.BaseEncryptor.SecretKey
		if n, err := skIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), skIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := skOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), skIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, skIn, skOut)
	})

	t.Run("EvaluationKey", func(t *testing.T) {
		var evkIn, evkOut tfhe.EvaluationKey[uint32]

		evkIn = testEvaluator.BaseEvaluator.EvaluationKey
		if n, err := evkIn.WriteTo(&buf); err != nil {
			assert.Equal(t, int(n), evkIn.ByteSize())
			assert.Error(t, err)
		}

		if n, err := evkOut.ReadFrom(&buf); err != nil {
			assert.Equal(t, int(n), evkIn.ByteSize())
			assert.Error(t, err)
		}

		assert.Equal(t, evkIn, evkOut)
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := testEncryptor.EncryptLWEBool(true)
	ct1 := testEncryptor.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(testParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		testEvaluator.ANDAssign(ct0, ct1, ctOut)
	}
}
