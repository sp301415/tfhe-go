package tfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe"
	"github.com/stretchr/testify/assert"
)

var params = tfhe.BooleanParameters

func TestEncrypter(t *testing.T) {
	enc := tfhe.NewEncrypter(params)
	msgs := []int{0, 1}

	t.Run("LWE", func(t *testing.T) {
		for _, msg := range msgs {
			ct := enc.EncryptLWE(msg)
			assert.Equal(t, msg, enc.DecryptLWE(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc.EncryptGLWE(msgs)
		assert.Equal(t, msgs, enc.DecryptGLWE(ct)[:len(msgs)])
	})
}
