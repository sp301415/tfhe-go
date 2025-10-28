package mktfhe_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/sp301415/tfhe-go/mktfhe"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	paramsBinary = mktfhe.ParamsBinaryParty4.Compile()
	encBinary    = []*mktfhe.BinaryEncryptor[uint64]{
		mktfhe.NewBinaryEncryptor(paramsBinary, 0, nil),
		mktfhe.NewBinaryEncryptor(paramsBinary, 1, nil),
	}
	evalBinary = mktfhe.NewBinaryEvaluator(paramsBinary, map[int]mktfhe.EvaluationKey[uint64]{
		0: encBinary[0].GenEvalKeyParallel(),
		1: encBinary[1].GenEvalKeyParallel(),
	})
	decBinary = mktfhe.NewBinaryDecryptor(paramsBinary, map[int]tfhe.SecretKey[uint64]{
		0: encBinary[0].Encryptor.SecretKey,
		1: encBinary[1].Encryptor.SecretKey,
	})
)

func TestBinaryParams(t *testing.T) {
	t.Run("ParamsBinaryParty2", func(t *testing.T) {
		assert.NotPanics(t, func() { mktfhe.ParamsBinaryParty2.Compile() })
	})

	t.Run("ParamsBinaryParty4", func(t *testing.T) {
		assert.NotPanics(t, func() { mktfhe.ParamsBinaryParty4.Compile() })
	})

	t.Run("ParamsBinaryParty8", func(t *testing.T) {
		assert.NotPanics(t, func() { mktfhe.ParamsBinaryParty8.Compile() })
	})

	t.Run("ParamsBinaryParty16", func(t *testing.T) {
		assert.NotPanics(t, func() { mktfhe.ParamsBinaryParty16.Compile() })
	})

	t.Run("ParamsBinaryParty32", func(t *testing.T) {
		assert.NotPanics(t, func() { mktfhe.ParamsBinaryParty32.Compile() })
	})
}

func TestBinaryEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 mktfhe.LWECiphertext[uint64]
		ct1 mktfhe.LWECiphertext[uint64]
	}{
		{true, true, encBinary[0].EncryptLWEBool(true), encBinary[1].EncryptLWEBool(true)},
		{true, false, encBinary[0].EncryptLWEBool(true), encBinary[1].EncryptLWEBool(false)},
		{false, true, encBinary[0].EncryptLWEBool(false), encBinary[1].EncryptLWEBool(true)},
		{false, false, encBinary[0].EncryptLWEBool(false), encBinary[1].EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, decBinary.DecryptLWEBool(evalBinary.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("ANDParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, decBinary.DecryptLWEBool(evalBinary.ANDParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), decBinary.DecryptLWEBool(evalBinary.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NANDParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), decBinary.DecryptLWEBool(evalBinary.NANDParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, decBinary.DecryptLWEBool(evalBinary.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("ORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, decBinary.DecryptLWEBool(evalBinary.ORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), decBinary.DecryptLWEBool(evalBinary.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), decBinary.DecryptLWEBool(evalBinary.NORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, decBinary.DecryptLWEBool(evalBinary.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, decBinary.DecryptLWEBool(evalBinary.XORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, decBinary.DecryptLWEBool(evalBinary.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNORParallel", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, decBinary.DecryptLWEBool(evalBinary.XNORParallel(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := encBinary[0].EncryptLWEBits(msg0, 4)
		ct1 := encBinary[1].EncryptLWEBits(msg1, 4)

		ctOut := encBinary[0].EncryptLWEBits(0, 4)
		for i := range ctOut {
			evalBinary.XORTo(ctOut[i], ct0[i], ct1[i])
		}

		assert.Equal(t, decBinary.DecryptLWEBits(ctOut), msg0^msg1)
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := encBinary[0].EncryptLWEBool(true)
	ct1 := encBinary[1].EncryptLWEBool(false)
	ctOut := mktfhe.NewLWECiphertext(paramsBinary)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		evalBinary.ANDTo(ctOut, ct0, ct1)
	}
}

func BenchmarkGateBootstrapParallel(b *testing.B) {
	ct0 := encBinary[0].EncryptLWEBool(true)
	ct1 := encBinary[1].EncryptLWEBool(false)
	ctOut := mktfhe.NewLWECiphertext(paramsBinary)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		evalBinary.ANDParallelTo(ctOut, ct0, ct1)
	}
}

func ExampleBinaryEvaluator() {
	// This parameters can take up to two parties.
	params := mktfhe.ParamsBinaryParty2.Compile()

	// Sample a seed for CRS.
	seed := make([]byte, 512)
	rand.Read(seed)

	// Each Encryptor should be marked with index.
	enc0 := mktfhe.NewBinaryEncryptor(params, 0, seed)
	enc1 := mktfhe.NewBinaryEncryptor(params, 1, seed)

	// Set up Decryptor.
	// In practice, one should use a distributed decryption protocol
	// to decrypt multi-key ciphertexts.
	// However, in multi-key TFHE, this procedure is very difficult and slow.
	// Therefore, we use a trusted third party for decryption.
	dec := mktfhe.NewBinaryDecryptor(params, map[int]tfhe.SecretKey[uint64]{
		0: enc0.Encryptor.SecretKey,
		1: enc1.Encryptor.SecretKey,
	})

	ct0 := enc0.EncryptLWEBool(true)
	ct1 := enc1.EncryptLWEBool(false)

	// Set up Evaluator.
	eval := mktfhe.NewBinaryEvaluator(params, map[int]mktfhe.EvaluationKey[uint64]{
		0: enc0.GenEvalKeyParallel(),
		1: enc1.GenEvalKeyParallel(),
	})

	// Execute AND operation in parallel.
	ctOut := eval.ANDParallel(ct0, ct1)

	fmt.Println(dec.DecryptLWEBool(ctOut))
	// Output:
	// false
}
