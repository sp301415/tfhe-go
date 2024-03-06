package mktfhe_test

import (
	"bytes"
	"testing"

	"github.com/sp301415/tfhe-go/mktfhe"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams     = mktfhe.ParamsBinaryParty4.Compile()
	testEncryptors = []*mktfhe.Encryptor[uint64]{
		mktfhe.NewEncryptor(testParams, 0, nil),
		mktfhe.NewEncryptor(testParams, 1, nil),
	}
	testEvaluator = mktfhe.NewEvaluator(testParams, map[int]mktfhe.EvaluationKey[uint64]{
		0: testEncryptors[0].GenEvaluationKeyParallel(),
		1: testEncryptors[1].GenEvaluationKeyParallel(),
	})
	testDecryptor = mktfhe.NewDecryptor(testParams, map[int]tfhe.SecretKey[uint64]{
		0: testEncryptors[0].SecretKey,
		1: testEncryptors[1].SecretKey,
	})
)

func TestEncryptor(t *testing.T) {
	messages := []int{1, 2, 3}
	gadgetParams := testParams.RelinKeyParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptors[0].EncryptLWE(m)
			assert.Equal(t, m, testDecryptor.DecryptLWE(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncryptors[0].EncryptGLWE(messages)
		assert.Equal(t, messages, testDecryptor.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("UniEncryption", func(t *testing.T) {
		ct := testEncryptors[0].UniEncrypt(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptors[0].UniDecrypt(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := testEncryptors[0].EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testDecryptor.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierUniEncryption", func(t *testing.T) {
		ct := testEncryptors[0].FourierUniEncrypt(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptors[0].FourierUniDecrypt(ct)[:len(messages)])
	})
}

func TestEvaluator(t *testing.T) {
	messages := []int{1, 2}

	t.Run("HybridProduct", func(t *testing.T) {
		ct := testEncryptors[0].EncryptGLWE(messages)

		mul := 2
		ctMul := testEncryptors[0].FourierUniEncrypt([]int{mul}, testParams.RelinKeyParameters())

		ctOut := testEvaluator.HybridProduct(0, ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, (mul*m)%int(testParams.MessageModulus()), testDecryptor.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("ExternalProduct", func(t *testing.T) {
		ct := testEncryptors[0].EncryptGLWE(messages)

		mul := 2
		ctMul := testEncryptors[0].SingleKeyEncryptor.EncryptFourierGLev([]int{mul}, testParams.AccumulatorParameters())

		ctOut := testEvaluator.ExternalProduct(0, ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, (mul*m)%int(testParams.MessageModulus()), testDecryptor.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return x + 1 }
		for _, m := range messages {
			ct := testEncryptors[0].EncryptLWE(m)
			ctOut := testEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testDecryptor.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapFuncParallel", func(t *testing.T) {
		f := func(x int) int { return x + 1 }
		for _, m := range messages {
			ct := testEncryptors[0].EncryptLWE(m)
			ctOut := testEvaluator.BootstrapFuncParallel(ct, f)
			assert.Equal(t, f(m), testDecryptor.DecryptLWE(ctOut))
		}
	})
}

func TestMarshal(t *testing.T) {
	var n int64
	var err error
	var buf bytes.Buffer

	t.Run("Parameters", func(t *testing.T) {
		var paramsIn, paramsOut mktfhe.Parameters[uint64]

		paramsIn = testParams
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

		ctIn = testEncryptors[0].EncryptLWE(0)
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

		ctIn = testEncryptors[0].EncryptGLWE([]int{0})
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FourierGLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut mktfhe.FourierGLWECiphertext[uint64]

		ctIn = testEncryptors[0].EncryptFourierGLWE([]int{0})
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

		ctIn = testEncryptors[0].UniEncrypt([]int{0}, testParams.RelinKeyParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FourierUniEncryption", func(t *testing.T) {
		var ctIn, ctOut mktfhe.FourierUniEncryption[uint64]

		ctIn = testEncryptors[0].FourierUniEncrypt([]int{0}, testParams.RelinKeyParameters())
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

		evkIn = testEvaluator.EvaluationKeys[0]
		n, err = evkIn.WriteTo(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		n, err = evkOut.ReadFrom(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, evkIn, evkOut)
	})
}
