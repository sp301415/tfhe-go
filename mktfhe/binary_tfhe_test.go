package mktfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/mktfhe"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testBinaryParams     = mktfhe.ParamsBinaryParty4.Compile()
	testBinaryEncryptors = []*mktfhe.BinaryEncryptor[uint64]{
		mktfhe.NewBinaryEncryptor(testBinaryParams, 0, nil),
		mktfhe.NewBinaryEncryptor(testBinaryParams, 1, nil),
	}
	testBinaryEvaluator = mktfhe.NewBinaryEvaluator(testBinaryParams, map[int]mktfhe.EvaluationKey[uint64]{
		0: testBinaryEncryptors[0].GenEvaluationKeyParallel(),
		1: testBinaryEncryptors[1].GenEvaluationKeyParallel(),
	})
	testBinaryDecryptor = mktfhe.NewBinaryDecryptor(testBinaryParams, map[int]tfhe.SecretKey[uint64]{
		0: testBinaryEncryptors[0].BaseEncryptor.SecretKey,
		1: testBinaryEncryptors[1].BaseEncryptor.SecretKey,
	})
)

func TestBinaryEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 mktfhe.LWECiphertext[uint64]
		ct1 mktfhe.LWECiphertext[uint64]
	}{
		{true, true, testBinaryEncryptors[0].EncryptLWEBool(true), testBinaryEncryptors[1].EncryptLWEBool(true)},
		{true, false, testBinaryEncryptors[0].EncryptLWEBool(true), testBinaryEncryptors[1].EncryptLWEBool(false)},
		{false, true, testBinaryEncryptors[0].EncryptLWEBool(false), testBinaryEncryptors[1].EncryptLWEBool(true)},
		{false, false, testBinaryEncryptors[0].EncryptLWEBool(false), testBinaryEncryptors[1].EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("ANDParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.ANDParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NANDParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.NANDParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("ORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.ORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.NORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.XORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, testBinaryDecryptor.DecryptLWEBool(testBinaryEvaluator.XNORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := testBinaryEncryptors[0].EncryptLWEBits(msg0, 4)
		ct1 := testBinaryEncryptors[1].EncryptLWEBits(msg1, 4)

		ctOut := testBinaryEncryptors[0].EncryptLWEBits(0, 4)
		for i := range ctOut {
			testBinaryEvaluator.XORAssign(ct0[i], ct1[i], ctOut[i])
		}

		assert.Equal(t, testBinaryDecryptor.DecryptLWEBits(ctOut), msg0^msg1)
	})
}
