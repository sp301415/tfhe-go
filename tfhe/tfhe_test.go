package tfhe_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams          = tfhe.ParamsUint3.Compile()
	testEncryptor       = tfhe.NewEncryptor(testParams)
	testPublicEncryptor = testEncryptor.PublicEncryptor()
	testEvaluator       = tfhe.NewEvaluator(testParams, testEncryptor.GenEvaluationKeyParallel())

	benchParams    = tfhe.ParamsUint6.Compile()
	benchEncryptor = tfhe.NewEncryptor(benchParams)
	benchEvaluator = tfhe.NewEvaluator(benchParams, benchEncryptor.GenEvaluationKeyParallel())
)

func TestParams(t *testing.T) {
	t.Run("ParamsUint2", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint2.Compile() })
	})

	t.Run("ParamsUint3", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint3.Compile() })
	})

	t.Run("ParamsUint4", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint4.Compile() })
	})

	t.Run("ParamsUint5", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint5.Compile() })
	})

	t.Run("ParamsUint6", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint6.Compile() })
	})

	t.Run("ParamsUint7", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint7.Compile() })
	})

	t.Run("ParamsUint8", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsUint8.Compile() })
	})
}

func TestEncryptor(t *testing.T) {
	messages := []int{1, 2, 3}
	gadgetParams := testParams.KeySwitchParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptLWE(m)
			assert.Equal(t, m, testEncryptor.DecryptLWE(ct))
		}
	})

	t.Run("PublicLWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testPublicEncryptor.EncryptLWE(m)
			assert.Equal(t, m, testEncryptor.DecryptLWE(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptLev(m, gadgetParams)
			assert.Equal(t, m, testEncryptor.DecryptLev(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptGSW(m, gadgetParams)
			assert.Equal(t, m, testEncryptor.DecryptGSW(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncryptor.EncryptGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("PublicGLWE", func(t *testing.T) {
		ct := testPublicEncryptor.EncryptGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := testEncryptor.EncryptGLev(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptor.DecryptGLev(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := testEncryptor.EncryptGGSW(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptor.DecryptGGSW(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("PublicFourierGLWE", func(t *testing.T) {
		ct := testPublicEncryptor.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierGLev", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGLev(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGLev(ct)[:len(messages)])
	})

	t.Run("FourierGGSW", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGGSW(messages, gadgetParams)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGGSW(ct)[:len(messages)])
	})
}

func TestEvaluator(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProduct", func(t *testing.T) {
		ct := testEncryptor.EncryptGLWE(messages)

		mul := 2
		ctMul := testEncryptor.EncryptFourierGGSW([]int{mul}, testParams.KeySwitchParameters())

		ctOut := testEvaluator.ExternalProduct(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, testEncryptor.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := testEncryptor.EncryptGLWE(messagesPool[0])
			ct1 := testEncryptor.EncryptGLWE(messagesPool[1])
			ctGGSW := testEncryptor.EncryptFourierGGSW([]int{i}, testParams.BootstrapParameters())

			ctOut := testEvaluator.CMux(ctGGSW, ct0, ct1)

			assert.Equal(t, messagesPool[i], testEncryptor.DecryptGLWE(ctOut)[:len(messages)])
		}
	})

	t.Run("BootstrapOriginalFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		paramsOriginalBootstrapLiteral := testParams.Literal()
		paramsOriginalBootstrapLiteral.BlockSize = 1
		paramsOriginalBootstrap := paramsOriginalBootstrapLiteral.Compile()

		originalEncryptor := tfhe.NewEncryptor(paramsOriginalBootstrap)
		originalEvaluator := tfhe.NewEvaluator(paramsOriginalBootstrap, originalEncryptor.GenEvaluationKeyParallel())

		for _, m := range messages {
			ct := originalEncryptor.EncryptLWE(m)
			ctOut := originalEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), originalEncryptor.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapBlockFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncryptor.EncryptLWE(m)
			ctOut := testEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncryptor.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapExtendedFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := benchEncryptor.EncryptLWE(m)
			ctOut := benchEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), benchEncryptor.DecryptLWE(ctOut))
		}
	})
}

func TestMarshal(t *testing.T) {
	var n int64
	var err error
	var buf bytes.Buffer

	t.Run("Parameters", func(t *testing.T) {
		var paramsIn, paramsOut tfhe.Parameters[uint64]

		paramsIn = testParams
		n, err := paramsIn.WriteTo(&buf)
		assert.Equal(t, int(n), paramsIn.ByteSize())
		assert.NoError(t, err)

		n, err = paramsOut.ReadFrom(&buf)
		assert.Equal(t, int(n), paramsIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, paramsIn, paramsOut)
	})

	t.Run("LWECiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.LWECiphertext[uint64]

		ctIn = testEncryptor.EncryptLWE(0)
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("LevCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.LevCiphertext[uint64]

		ctIn = testEncryptor.EncryptLev(0, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GSWCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GSWCiphertext[uint64]

		ctIn = testEncryptor.EncryptGSW(0, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GLWECiphertext[uint64]

		ctIn = testEncryptor.EncryptGLWE([]int{0})
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GLevCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GLevCiphertext[uint64]

		ctIn = testEncryptor.EncryptGLev([]int{0}, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("GGSWCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.GGSWCiphertext[uint64]

		ctIn = testEncryptor.EncryptGGSW([]int{0}, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FourierGLWECiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.FourierGLWECiphertext[uint64]

		ctIn = testEncryptor.EncryptFourierGLWE([]int{0})
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FourierGLevCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.FourierGLevCiphertext[uint64]

		ctIn = testEncryptor.EncryptFourierGLev([]int{0}, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("FourierGGSWCiphertext", func(t *testing.T) {
		var ctIn, ctOut tfhe.FourierGGSWCiphertext[uint64]

		ctIn = testEncryptor.EncryptFourierGGSW([]int{0}, testParams.KeySwitchParameters())
		n, err = ctIn.WriteTo(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		n, err = ctOut.ReadFrom(&buf)
		assert.Equal(t, int(n), ctIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, ctIn, ctOut)
	})

	t.Run("SecretKey", func(t *testing.T) {
		var skIn, skOut tfhe.SecretKey[uint64]

		skIn = testEncryptor.GenSecretKey()
		n, err = skIn.WriteTo(&buf)
		assert.Equal(t, int(n), skIn.ByteSize())
		assert.NoError(t, err)

		n, err = skOut.ReadFrom(&buf)
		assert.Equal(t, int(n), skIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, skIn, skOut)
	})

	t.Run("PublicKey", func(t *testing.T) {
		var pkIn, pkOut tfhe.PublicKey[uint64]

		pkIn = testEncryptor.GenPublicKey()
		n, err = pkIn.WriteTo(&buf)
		assert.Equal(t, int(n), pkIn.ByteSize())
		assert.NoError(t, err)

		n, err = pkOut.ReadFrom(&buf)
		assert.Equal(t, int(n), pkIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, pkIn, pkOut)
	})

	t.Run("EvaluationKey", func(t *testing.T) {
		var evkIn, evkOut tfhe.EvaluationKey[uint64]

		evkIn = testEvaluator.EvaluationKey
		n, err = evkIn.WriteTo(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		n, err = evkOut.ReadFrom(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, evkIn, evkOut)
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchEncryptor.GenEvaluationKeyParallel()
	}
}

func BenchmarkProgrammableBootstrap(b *testing.B) {
	ct := benchEncryptor.EncryptLWE(3)
	lut := benchEvaluator.GenLookUpTable(func(x int) int { return 2*x + 1 })
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluator.BootstrapLUTAssign(ct, lut, ct)
	}
}

func ExampleEncryptor() {
	params := tfhe.ParamsUint4.Compile() // Parameters must be compiled before use.

	enc := tfhe.NewEncryptor(params) // Set up Encryptor.

	ctLWE := enc.EncryptLWE(4)
	ctGLWE := enc.EncryptGLWE([]int{1, 2, 3, 4})

	// Decrypt Everything!
	fmt.Println(enc.DecryptLWE(ctLWE))       // 4
	fmt.Println(enc.DecryptGLWE(ctGLWE)[:4]) // [1, 2, 3, 4]
}

func ExampleEvaluator_CMux() {
	params := tfhe.ParamsUint4.Compile()
	gadgetParams := tfhe.GadgetParametersLiteral[uint64]{
		Base:  1 << 3,
		Level: 6,
	}.Compile()

	enc := tfhe.NewEncryptor(params)

	ct0 := enc.EncryptGLWE([]int{2})
	ct1 := enc.EncryptGLWE([]int{5})
	ctFlag := enc.EncryptFourierGGSW([]int{1}, gadgetParams)

	// We don't need evaluation key for CMUX.
	eval := tfhe.NewEvaluatorWithoutKey(params)

	ctOut := eval.CMux(ctFlag, ct0, ct1)
	fmt.Println(enc.DecryptGLWE(ctOut)[0]) // 5
}

func ExampleEvaluator_BootstrapFunc() {
	params := tfhe.ParamsUint4.Compile()

	enc := tfhe.NewEncryptor(params)

	ct := enc.EncryptLWE(3)

	eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	ctOut := eval.BootstrapFunc(ct, func(x int) int { return 2*x + 1 })
	fmt.Println(enc.DecryptLWE(ctOut)) // 7 = 2*3+1
}
