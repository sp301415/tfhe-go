package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe"
	"github.com/stretchr/testify/assert"
)

var params = tfhe.ParamsMessage4Carry0

func TestEncrypter(t *testing.T) {
	enc := tfhe.NewEncrypter(params)
	msgs := []int{2, 4, 8}

	t.Run("LWE", func(t *testing.T) {
		for _, msg := range msgs {
			ct := enc.MustEncrypt(msg)
			assert.Equal(t, msg, enc.Decrypt(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc.MustEncryptPacked(msgs)
		assert.Equal(t, msgs, enc.DecryptPacked(ct)[:len(msgs)])
	})
}
