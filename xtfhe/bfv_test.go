package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	bfvParams          = tfhe.ParamsUint3.Compile()
	bfvKeySwitchParams = xtfhe.ParamsBFVKeySwitchLogN11.Compile()
	bfvEnc             = tfhe.NewEncryptor(bfvParams)
	bfvKeyGen          = xtfhe.NewBFVKeyGenerator(bfvParams, bfvEnc.SecretKey)
	bfvEval            = xtfhe.NewBFVEvaluator(bfvParams, xtfhe.BFVEvaluationKey[uint64]{
		RelinKey:   bfvKeyGen.GenRelinKey(bfvKeySwitchParams),
		GaloisKeys: bfvKeyGen.GenGaloisKeysForLWEToGLWECiphertext(bfvKeySwitchParams),
	})
)

func TestBFVMul(t *testing.T) {
	m0 := int(num.Sqrt(bfvParams.MessageModulus()) - 1)
	m1 := int(num.Sqrt(bfvParams.MessageModulus()) - 2)

	ct0 := bfvEnc.EncryptGLWE([]int{m0})
	ct1 := bfvEnc.EncryptGLWE([]int{m1})

	ctMul := bfvEval.Mul(ct0, ct1)

	assert.Equal(t, bfvEnc.DecryptGLWE(ctMul)[0], m0*m1)
}

func TestBFVPermute(t *testing.T) {
	m0 := 1
	m1 := 1
	d := 1<<5 + 1

	ct0 := bfvEnc.EncryptGLWE([]int{m0, m1})
	ctAut := bfvEval.Permute(ct0, d)

	assert.Equal(t, bfvEnc.DecryptGLWE(ctAut)[0], m0)
	assert.Equal(t, bfvEnc.DecryptGLWE(ctAut)[d], m1)
}

func TestLWEToGLWECiphertext(t *testing.T) {
	m := 3
	ctLWE := bfvEnc.EncryptLWE(m)
	ctGLWE := bfvEval.LWEToGLWECiphertext(ctLWE)

	assert.Equal(t, bfvEnc.DecryptGLWE(ctGLWE)[0], m)
}

func BenchmarkBFVMul(b *testing.B) {
	ct0 := bfvEnc.EncryptGLWE(nil)
	ct1 := bfvEnc.EncryptGLWE(nil)
	ctMul := bfvEnc.EncryptGLWE(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bfvEval.MulTo(ctMul, ct0, ct1)
	}
}

func BenchmarkBFVRingPack(b *testing.B) {
	ctLWE := bfvEnc.EncryptLWE(0)
	ctGLWE := bfvEnc.EncryptGLWE(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bfvEval.LWEToGLWECiphertextTo(ctGLWE, ctLWE)
	}
}
