package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var params = tfhe.ParamsMessage8Carry0

func TestEncrypter(t *testing.T) {
	enc := tfhe.NewEncrypter(params)
	msgs := []int{2, 4, 8}

	t.Run("LWE", func(t *testing.T) {
		for _, msg := range msgs {
			ct := enc.Encrypt(msg)
			assert.Equal(t, msg, enc.Decrypt(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc.EncryptPacked(msgs)
		assert.Equal(t, msgs, enc.DecryptPacked(ct)[:len(msgs)])
	})
}

func TestEvaluater(t *testing.T) {
	enc := tfhe.NewEncrypter(params)
	eval := tfhe.NewEvaluaterWithoutKey(params)
	msgs := []int{1, 2, 4, 8}

	t.Run("KeySwitch", func(t *testing.T) {
		encOut := tfhe.NewEncrypter(params)
		ksk := encOut.GenKeySwitchingKey(enc.LWEKey(), params.KeySwitchParameters())

		for _, msg := range msgs {
			ct := enc.Encrypt(msg)
			ctOut := eval.KeySwitch(ct, ksk)
			assert.Equal(t, msg, encOut.Decrypt(ctOut))
		}
	})
}

func BenchmarkKeyGen(b *testing.B) {
	enc := tfhe.NewEncrypterWithoutKey(params)

	b.Run("LWE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenLWEKey()
		}
	})

	b.Run("GLWE", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenGLWEKey()
		}
	})

	enc.SetLWEKey(enc.GenLWEKey())
	enc.SetGLWEKey(enc.GenGLWEKey())

	b.Run("KeySwitchingKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenKeySwitchingKeyForBootstrapping()
		}
	})

	b.Run("KeySwitchingKeyParallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenKeySwitchingKeyForBootstrappingParallel()
		}
	})

	b.Run("BootstrappingKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenBootstrappingKey()
		}
	})

	b.Run("BootstrappingKeyParallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc.GenBootstrappingKeyParallel()
		}
	})
}
