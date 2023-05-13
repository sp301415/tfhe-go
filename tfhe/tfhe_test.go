package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsUint4.Compile()
	benchParams = tfhe.ParamsUint8.Compile()
)

func TestEncrypter(t *testing.T) {
	enc := tfhe.NewEncrypter(testParams)
	messages := []int{2, 4, 8}

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := enc.Encrypt(m)
			assert.Equal(t, m, enc.Decrypt(ct))
		}
	})

	t.Run("LWELarge", func(t *testing.T) {
		for _, m := range messages {
			ct := enc.EncryptLarge(m)
			assert.Equal(t, m, enc.DecryptLarge(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc.EncryptPacked(messages)
		assert.Equal(t, messages, enc.DecryptPacked(ct)[:len(messages)])
	})
}

func TestEvaluater(t *testing.T) {
	enc := tfhe.NewEncrypter(testParams)
	eval := tfhe.NewEvaluater(testParams, enc.GenEvaluationKeyParallel())
	messages := []int{1, 2, 3, 4}

	t.Run("ExternalProductFourier", func(t *testing.T) {
		ctGLWE := enc.EncryptPacked(messages)
		messages2 := []int{3}
		ctGGSW := enc.EncryptPackedForMul(messages2, enc.Parameters.KeySwitchParameters())
		ctOut := eval.ExternalProductFourier(ctGGSW, ctGLWE)

		assert.Equal(t, messages[0]*messages2[0], enc.DecryptPacked(ctOut)[0])
	})

	t.Run("CMUX", func(t *testing.T) {
		ctGLWE0 := enc.EncryptPacked([]int{messages[0]})
		ctGLWE1 := enc.EncryptPacked([]int{messages[1]})
		for i := 0; i <= 1; i++ {
			ctGGSW := enc.EncryptPackedForMul([]int{i}, enc.Parameters.BootstrapParameters())
			ctOut := eval.CMuxFourier(ctGGSW, ctGLWE0, ctGLWE1)

			assert.Equal(t, messages[i], enc.DecryptPacked(ctOut)[0])
		}
	})

	t.Run("BlindRotate", func(t *testing.T) {
		ct := enc.Encrypt(messages[0])
		f := func(x int) int { return 2 * x }
		ctOut := eval.BlindRotateFunc(ct, f)
		assert.Equal(t, f(messages[0]), enc.DecryptPacked(ctOut)[0])
	})

	t.Run("KeySwitch", func(t *testing.T) {
		for _, msg := range messages {
			ct := enc.EncryptLarge(msg)
			ctOut := eval.KeySwitchForBootstrap(ct)
			assert.Equal(t, msg, enc.Decrypt(ctOut))
		}
	})

	t.Run("SampleExtract", func(t *testing.T) {
		index := 0

		ct := enc.EncryptPacked(messages)
		ctExtracted := eval.SampleExtract(ct, index)
		assert.Equal(t, messages[index], enc.DecryptLarge(ctExtracted))
	})
}

func BenchmarkEncryption(b *testing.B) {
	enc := tfhe.NewEncrypter(benchParams)
	messages := []int{1, 2, 3, 4}

	b.Run("LWE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.Encrypt(messages[0])
		}
	})

	b.Run("LWELarge", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.EncryptLarge(messages[0])
		}
	})

	b.Run("GLWE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.EncryptPacked(messages)
		}
	})
}

func BenchmarkKeySwitchingKeyGen(b *testing.B) {
	enc := tfhe.NewEncrypter(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc.GenKeySwitchingKeyForBootstrappingParallel()
	}
}

func BenchmarkBootstrappingKeyGen(b *testing.B) {
	enc := tfhe.NewEncrypter(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc.GenBootstrappingKeyParallel()
	}
}
