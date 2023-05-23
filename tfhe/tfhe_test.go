package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/vec"
	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsUint3.Compile()
	benchParams = tfhe.ParamsUint6.Compile()

	testEncrypter = tfhe.NewEncrypter(testParams)
	testEvaluater = tfhe.NewEvaluater(testParams, testEncrypter.GenEvaluationKeyParallel())

	benchEncrypter = tfhe.NewEncrypter(benchParams)
	benchEvaluater = tfhe.NewEvaluater(benchParams, benchEncrypter.GenEvaluationKeyParallel())
)

func TestEncrypter(t *testing.T) {
	messages := []int{1, 2, 3}
	decompParams := testParams.KeySwitchParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLWE(m)
			assert.Equal(t, m, testEncrypter.DecryptLWE(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLev(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptLev(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptGSW(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptGSW(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWE(messages)
		assert.Equal(t, messages, testEncrypter.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := testEncrypter.EncryptGLev(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGLev(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := testEncrypter.EncryptGGSW(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGGSW(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierGLev", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGLev(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGLev(ct)[:len(messages)])
	})

	t.Run("FourierGGSW", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGGSW(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGGSW(ct)[:len(messages)])
	})
}

func TestEvaluater(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProductFourier", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWE(messages)

		mul := 2
		ctMul := testEncrypter.EncryptFourierGGSW([]int{mul}, testParams.KeySwitchParameters())

		ctOut := testEvaluater.ExternalProductFourier(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, testEncrypter.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := testEncrypter.EncryptGLWE(messagesPool[0])
			ct1 := testEncrypter.EncryptGLWE(messagesPool[1])
			ctGGSW := testEncrypter.EncryptFourierGGSW([]int{i}, testParams.BootstrapParameters())

			ctOut := testEvaluater.CMuxFourier(ctGGSW, ct0, ct1)

			assert.Equal(t, messagesPool[i], testEncrypter.DecryptGLWE(ctOut)[:len(messages)])
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncrypter.EncryptLWE(m)
			ctOut := testEvaluater.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncrypter.DecryptLWE(ctOut))
		}
	})

	t.Run("LWEMul", func(t *testing.T) {
		ct0 := testEncrypter.EncryptLWE(messages[0])
		ct1 := testEncrypter.EncryptLWE(messages[1])

		ctOut := testEvaluater.MulLWE(ct0, ct1)

		assert.Equal(t, messages[0]*messages[1], testEncrypter.DecryptLWE(ctOut))
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchEncrypter.GenEvaluationKeyParallel()
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := benchEncrypter.EncryptLWE(3)
	ctOut := tfhe.NewLWECiphertext(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluater.BootstrapInPlace(ct, ctOut)
	}
}
