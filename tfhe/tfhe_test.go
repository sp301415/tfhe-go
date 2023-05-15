package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/vec"
	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsUint3Carry0.Compile()
	benchParams = tfhe.ParamsUint6Carry0.Compile()

	testEncrypter = tfhe.NewEncrypter(testParams)
	testEvaluater = tfhe.NewEvaluater(testParams, testEncrypter.GenEvaluationKeyParallel())

	benchEncrypter = tfhe.NewEncrypter(benchParams)
	benchEvaluater = tfhe.NewEvaluater(benchParams, benchEncrypter.GenEvaluationKeyParallel())
)

func TestEncrypter(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.Encrypt(m)
			assert.Equal(t, m, testEncrypter.Decrypt(ct))
		}
	})

	t.Run("LWELarge", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLarge(m)
			assert.Equal(t, m, testEncrypter.DecryptLarge(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptPacked(messages)
		assert.Equal(t, messages, testEncrypter.DecryptPacked(ct)[:len(messages)])
	})
}

func TestEvaluater(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProductFourier", func(t *testing.T) {
		ct := testEncrypter.EncryptPacked(messages)

		mul := 2
		ctMul := testEncrypter.EncryptPackedForMul([]int{mul}, testParams.KeySwitchParameters())

		ctOut := testEvaluater.ExternalProductFourier(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, testEncrypter.DecryptPacked(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := testEncrypter.EncryptPacked(messagesPool[0])
			ct1 := testEncrypter.EncryptPacked(messagesPool[1])
			ctGGSW := testEncrypter.EncryptPackedForMul([]int{i}, testParams.BootstrapParameters())

			ctOut := testEvaluater.CMuxFourier(ctGGSW, ct0, ct1)

			assert.Equal(t, messagesPool[i], testEncrypter.DecryptPacked(ctOut)[:len(messages)])
		}
	})

	t.Run("BlindRotate", func(t *testing.T) {
		f := func(x int) int { return 2 * x }
		lut := testEvaluater.GenLookUpTable(f)

		for _, m := range messages {
			ct := testEncrypter.Encrypt(m)
			ctOut := testEvaluater.BlindRotate(ct, lut)
			assert.Equal(t, f(m), testEncrypter.DecryptPacked(ctOut)[0])
		}
	})

	t.Run("KeySwitch", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLarge(m)
			ctOut := testEvaluater.KeySwitchForBootstrap(ct)
			assert.Equal(t, m, testEncrypter.Decrypt(ctOut))
		}
	})

	t.Run("SampleExtract", func(t *testing.T) {
		ct := testEncrypter.EncryptPacked(messages)

		for i, m := range messages {
			ctOut := testEvaluater.SampleExtract(ct, i)
			assert.Equal(t, m, testEncrypter.DecryptLarge(ctOut))
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncrypter.Encrypt(m)
			ctOut := testEvaluater.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncrypter.Decrypt(ctOut))
		}
	})

	t.Run("LWEMul", func(t *testing.T) {
		ct0 := testEncrypter.Encrypt(messages[0])
		ct1 := testEncrypter.Encrypt(messages[1])

		ctOut := testEvaluater.MulLWE(ct0, ct1)

		assert.Equal(t, messages[0]*messages[1], testEncrypter.Decrypt(ctOut))
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchEncrypter.GenEvaluationKeyParallel()
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := benchEncrypter.Encrypt(3)
	ctOut := tfhe.NewLWECiphertext(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluater.BootstrapInPlace(ct, ctOut)
	}
}
