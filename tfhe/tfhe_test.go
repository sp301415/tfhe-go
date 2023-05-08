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
		ksk := encOut.SampleKeySwitchingKeyFrom(enc.LWEKey(), params.KeySwitchParameters())

		for _, msg := range msgs {
			ct := enc.Encrypt(msg)
			ctOut := eval.KeySwitch(ct, ksk)
			assert.Equal(t, msg, encOut.Decrypt(ctOut))
		}
	})
}
