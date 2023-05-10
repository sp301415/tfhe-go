package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsMessage4Carry0.Compile()
	benchParams = tfhe.ParamsMessage8Carry0.Compile()
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
	ksk := enc.GenKeySwitchingKeyForBootstrappingParallel()

	eval := tfhe.NewEvaluaterWithoutKey(testParams)
	messages := []int{1, 2, 3, 4}

	t.Run("KeySwitch", func(t *testing.T) {
		for _, msg := range messages {
			ct := enc.EncryptLarge(msg)
			ctOut := eval.KeySwitch(ct, ksk)
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

func BenchmarkBootstrappingKeyGen(b *testing.B) {
	enc := tfhe.NewEncrypter(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc.GenBootstrappingKeyParallel()
	}
}
