package mktfhe_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sp301415/tfhe-go/mktfhe"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	params = mktfhe.ParamsBinaryParty4.Compile()
	enc    = []*mktfhe.Encryptor[uint64]{
		mktfhe.NewEncryptor(params, 0, nil),
		mktfhe.NewEncryptor(params, 1, nil),
	}
	eval = mktfhe.NewEvaluator(params, map[int]mktfhe.EvaluationKey[uint64]{
		0: enc[0].GenEvaluationKeyParallel(),
		1: enc[1].GenEvaluationKeyParallel(),
	})
	dec = mktfhe.NewDecryptor(params, map[int]tfhe.SecretKey[uint64]{
		0: enc[0].SecretKey,
		1: enc[1].SecretKey,
	})

	paramsList = []mktfhe.ParametersLiteral[uint64]{
		mktfhe.ParamsBinaryParty2,
		mktfhe.ParamsBinaryParty4,
		mktfhe.ParamsBinaryParty8,
		mktfhe.ParamsBinaryParty16,
		mktfhe.ParamsBinaryParty32,
	}
)

func TestParams(t *testing.T) {
	for _, params := range paramsList {
		t.Run(fmt.Sprintf("ParamsBinaryParty%v", params.PartyCount), func(t *testing.T) {
			assert.NotPanics(t, func() { params.Compile() })
		})
	}
}

func TestEncryptor(t *testing.T) {
	messages := []int{0, 1}
	gadgetParams := params.RelinKeyParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := enc[0].EncryptLWE(m)
			assert.Equal(t, m, dec.DecryptLWE(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc[0].EncryptGLWE(messages)
		assert.Equal(t, messages, dec.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("UniEncryption", func(t *testing.T) {
		ct := enc[0].UniEncrypt(messages, gadgetParams)
		assert.Equal(t, messages, enc[0].UniDecrypt(ct)[:len(messages)])
	})

	t.Run("FFTGLWE", func(t *testing.T) {
		ct := enc[0].EncryptFFTGLWE(messages)
		assert.Equal(t, messages, dec.DecryptFFTGLWE(ct)[:len(messages)])
	})

	t.Run("FFTUniEncryption", func(t *testing.T) {
		ct := enc[0].FFTUniEncrypt(messages, gadgetParams)
		assert.Equal(t, messages, enc[0].FFTUniDecrypt(ct)[:len(messages)])
	})
}

func TestEvaluator(t *testing.T) {
	messages := []int{0, 1}

	t.Run("HybridProduct", func(t *testing.T) {
		ct := enc[0].EncryptGLWE(messages)

		mul := 1
		ctMul := enc[0].FFTUniEncrypt([]int{mul}, params.RelinKeyParameters())

		ctOut := eval.HybridProdGLWE(0, ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, (mul*m)%int(params.MessageModulus()), dec.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("ExternalProduct", func(t *testing.T) {
		ct := enc[0].EncryptGLWE(messages)

		mul := 1
		ctMul := enc[0].SubEncryptor.EncryptFFTGLev([]int{mul}, params.AccumulatorParameters())

		ctOut := eval.ExternalProdGLWE(0, ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, (mul*m)%int(params.MessageModulus()), dec.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 1 - x }
		for _, m := range messages {
			ct := enc[0].EncryptLWE(m)
			ctOut := eval.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), dec.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapFuncParallel", func(t *testing.T) {
		f := func(x int) int { return 1 - x }
		for _, m := range messages {
			ct := enc[0].EncryptLWE(m)
			ctOut := eval.BootstrapFuncParallel(ct, f)
			assert.Equal(t, f(m), dec.DecryptLWE(ctOut))
		}
	})
}

func TestMarshal(t *testing.T) {
	var n int64
	var err error
	var buf bytes.Buffer

	t.Run("Parameters", func(t *testing.T) {
		var paramsIn, paramsOut mktfhe.Parameters[uint64]

		paramsIn = params
		n, err = paramsIn.WriteTo(&buf)
		assert.Equal(t, int(n), paramsIn.ByteSize())
		assert.NoError(t, err)

		n, err = paramsOut.ReadFrom(&buf)
		assert.Equal(t, int(n), paramsIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, paramsIn, paramsOut)
	})

	t.Run("LWECiphertext", func(t *testing.T) {
		var ctIn, ctOut mktfhe.LWECiphertext[uint64]

		ctIn = enc[0].EncryptLWE(0)
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut mktfhe.GLWECiphertext[uint64]

		ctIn = enc[0].EncryptGLWE([]int{0})
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FFTGLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut mktfhe.FFTGLWECiphertext[uint64]

		ctIn = enc[0].EncryptFFTGLWE([]int{0})
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("UniEncryption", func(t *testing.T) {
		var n int64
		var err error
		var ctIn, ctOut mktfhe.UniEncryption[uint64]

		ctIn = enc[0].UniEncrypt([]int{0}, params.RelinKeyParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FFTUniEncryption", func(t *testing.T) {
		var ctIn, ctOut mktfhe.FFTUniEncryption[uint64]

		ctIn = enc[0].FFTUniEncrypt([]int{0}, params.RelinKeyParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("EvaluationKey", func(t *testing.T) {
		var evkIn, evkOut mktfhe.EvaluationKey[uint64]

		evkIn = eval.EvalKey[0]
		n, err = evkIn.WriteTo(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		n, err = evkOut.ReadFrom(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, evkIn, evkOut)
	})
}
