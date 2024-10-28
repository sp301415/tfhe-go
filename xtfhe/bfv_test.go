package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	params = tfhe.ParamsUint6.Compile()
	enc    = tfhe.NewEncryptor(params)
	keyGen = xtfhe.NewBFVKeyGenerator(params, xtfhe.ParamsBFVKeySwitchLogN11.Compile(), enc.SecretKey)
	eval   = xtfhe.NewBFVEvaluator(params, xtfhe.BFVKeySwitchKey[uint64]{
		RelinKey:   keyGen.GenRelinKey(),
		GaloisKeys: keyGen.GenGaloisKeysForRingPack(),
	})
)

func TestBFVMul(t *testing.T) {
	m0 := int(num.Sqrt(params.MessageModulus()) - 1)
	m1 := int(num.Sqrt(params.MessageModulus()) - 2)

	ct0 := enc.EncryptGLWE([]int{m0})
	ct1 := enc.EncryptGLWE([]int{m1})

	ctMul := eval.Mul(ct0, ct1)

	assert.Equal(t, enc.DecryptGLWE(ctMul)[0], m0*m1)
}

func TestBFVPermute(t *testing.T) {
	m0 := 1
	m1 := 1
	d := 1<<5 + 1

	ct0 := enc.EncryptGLWE([]int{m0, m1})
	ctAut := eval.Permute(ct0, d)

	assert.Equal(t, enc.DecryptGLWE(ctAut)[0], m0)
	assert.Equal(t, enc.DecryptGLWE(ctAut)[d], m1)
}

func TestBFVRingPack(t *testing.T) {
	m := 3
	ctLWE := enc.EncryptLWE(m)
	ctGLWE := eval.RingPack(ctLWE)

	assert.Equal(t, enc.DecryptGLWE(ctGLWE)[0], m)
}

func BenchmarkBFVMul(b *testing.B) {
	ct0 := enc.EncryptGLWE(nil)
	ct1 := enc.EncryptGLWE(nil)
	ctMul := enc.EncryptGLWE(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.MulAssign(ct0, ct1, ctMul)
	}
}

func BenchmarkBFVRingPack(b *testing.B) {
	ctLWE := enc.EncryptLWE(0)
	ctGLWE := enc.EncryptGLWE(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.RingPackAssign(ctLWE, ctGLWE)
	}
}
