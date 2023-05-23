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
			ct := testEncrypter.EncryptLWEInt(m)
			assert.Equal(t, m, testEncrypter.DecryptLWEInt(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLevInt(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptLevInt(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptGSWInt(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptGSWInt(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWEInts(messages)
		assert.Equal(t, messages, testEncrypter.DecryptGLWEInts(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := testEncrypter.EncryptGLevInts(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGLevInts(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := testEncrypter.EncryptGGSWInts(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGGSWInts(ct)[:len(messages)])
	})
}

func TestEvaluater(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProductFourier", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWEInts(messages)

		mul := 2
		ctMulStandard := testEncrypter.EncryptGGSWInts([]int{mul}, testParams.KeySwitchParameters())
		ctMul := testEncrypter.ToFourierGGSWCiphertext(ctMulStandard)

		ctOut := testEvaluater.ExternalProductFourier(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, testEncrypter.DecryptGLWEInts(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := testEncrypter.EncryptGLWEInts(messagesPool[0])
			ct1 := testEncrypter.EncryptGLWEInts(messagesPool[1])
			ctGGSW := testEncrypter.EncryptGGSWInts([]int{i}, testParams.BootstrapParameters())
			ctGGSWF := testEncrypter.ToFourierGGSWCiphertext(ctGGSW)

			ctOut := testEvaluater.CMuxFourier(ctGGSWF, ct0, ct1)

			assert.Equal(t, messagesPool[i], testEncrypter.DecryptGLWEInts(ctOut)[:len(messages)])
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncrypter.EncryptLWEInt(m)
			ctOut := testEvaluater.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncrypter.DecryptLWEInt(ctOut))
		}
	})

	t.Run("LWEMul", func(t *testing.T) {
		ct0 := testEncrypter.EncryptLWEInt(messages[0])
		ct1 := testEncrypter.EncryptLWEInt(messages[1])

		ctOut := testEvaluater.MulLWE(ct0, ct1)

		assert.Equal(t, messages[0]*messages[1], testEncrypter.DecryptLWEInt(ctOut))
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchEncrypter.GenEvaluationKeyParallel()
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := benchEncrypter.EncryptLWEInt(3)
	ctOut := tfhe.NewLWECiphertext(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluater.BootstrapInPlace(ct, ctOut)
	}
}
