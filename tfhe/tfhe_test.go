package tfhe_test

import (
	"math"
	"testing"

	"github.com/sp301415/tfhe/math/vec"
	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsUint3.Compile()
	benchParams = tfhe.ParamsUint6.Compile()

	testEncrypter = tfhe.NewEncrypter(testParams)
	testEvaluater = tfhe.NewEvaluater(testParams, testEncrypter.GenEvaluationKeyParallel())

	benchEncrypter = tfhe.NewEncrypter(benchParams)
	benchEvaluater = tfhe.NewEvaluater(benchParams, benchEncrypter.GenEvaluationKeyParallel())
)

func TestEncrypter(t *testing.T) {
	messages := []int{1, 2, 3}
	decompParams := testParams.KeySwitchParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLWE(m)
			assert.Equal(t, m, testEncrypter.DecryptLWE(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptLev(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptLev(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncrypter.EncryptGSW(m, decompParams)
			assert.Equal(t, m, testEncrypter.DecryptGSW(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWE(messages)
		assert.Equal(t, messages, testEncrypter.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := testEncrypter.EncryptGLev(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGLev(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := testEncrypter.EncryptGGSW(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptGGSW(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierGLev", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGLev(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGLev(ct)[:len(messages)])
	})

	t.Run("FourierGGSW", func(t *testing.T) {
		ct := testEncrypter.EncryptFourierGGSW(messages, decompParams)
		assert.Equal(t, messages, testEncrypter.DecryptFourierGGSW(ct)[:len(messages)])
	})
}

func TestEvaluater(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProductFourier", func(t *testing.T) {
		ct := testEncrypter.EncryptGLWE(messages)

		mul := 2
		ctMul := testEncrypter.EncryptFourierGGSW([]int{mul}, testParams.KeySwitchParameters())

		ctOut := testEvaluater.ExternalProductFourier(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, testEncrypter.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := testEncrypter.EncryptGLWE(messagesPool[0])
			ct1 := testEncrypter.EncryptGLWE(messagesPool[1])
			ctGGSW := testEncrypter.EncryptFourierGGSW([]int{i}, testParams.BootstrapParameters())

			ctOut := testEvaluater.CMuxFourier(ctGGSW, ct0, ct1)

			assert.Equal(t, messagesPool[i], testEncrypter.DecryptGLWE(ctOut)[:len(messages)])
		}
	})

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncrypter.EncryptLWE(m)
			ctOut := testEvaluater.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncrypter.DecryptLWE(ctOut))
		}
	})

	t.Run("PrivateFunctionalLWEKeySwitch", func(t *testing.T) {
		sum := func(in []uint64) uint64 {
			return in[0] + in[1]
		}
		pfksk := testEncrypter.GenPrivateFunctionalLWEKeySwitchKeyParallel(2, sum, testParams.KeySwitchParameters())

		ct0 := testEncrypter.EncryptLWE(messages[0])
		ct1 := testEncrypter.EncryptLWE(messages[1])
		ctOut := testEvaluater.PrivateFunctionalLWEKeySwitch([]tfhe.LWECiphertext[uint64]{ct0, ct1}, pfksk)

		assert.Equal(t, messages[0]+messages[1], testEncrypter.DecryptLWE(ctOut))
	})

	t.Run("PublicFunctionalLWEKeySwitch", func(t *testing.T) {
		pfksk := testEncrypter.GenPublicFunctionalGLWEKeySwitchKeyParallel(testParams.KeySwitchParameters())

		ct0 := testEncrypter.EncryptLWE(messages[0])
		ct1 := testEncrypter.EncryptLWE(messages[1])
		ctOut := testEvaluater.PackingPublicFunctionalKeySwitch([]tfhe.LWECiphertext[uint64]{ct0, ct1}, pfksk)

		assert.Equal(t, []int{messages[0], messages[1]}, testEncrypter.DecryptGLWE(ctOut)[:2])
	})

	t.Run("CircuitBootstrap", func(t *testing.T) {
		cbsParams := tfhe.ParametersLiteral[uint64]{
			LWEDimension:  10,
			GLWEDimension: 2,
			PolyDegree:    512,

			LWEStdDev:  math.Exp2(-60),
			GLWEStdDev: math.Exp2(-60),

			MessageModulus: 1 << 3,

			BootstrapParameters: tfhe.DecompositionParametersLiteral[uint64]{
				Base:  1 << 15,
				Level: 2,
			},
			KeySwitchParameters: tfhe.DecompositionParametersLiteral[uint64]{
				Base:  1 << 15,
				Level: 2,
			},
		}.Compile()

		pfkskDecompParams := tfhe.DecompositionParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		}.Compile()

		cbsDecompParams := tfhe.DecompositionParametersLiteral[uint64]{
			Base:  1 << 10,
			Level: 1,
		}.Compile()

		enc := tfhe.NewEncrypter(cbsParams)
		defer enc.Free()

		eval := tfhe.NewEvaluater(cbsParams, enc.GenEvaluationKeyParallel())
		defer eval.Free()

		cbsk := enc.GenCircuitBootstrapKeyParallel(pfkskDecompParams)

		for _, m := range messages {
			ct := enc.EncryptLWE(m)
			ctOut := eval.CircuitBootstrap(ct, cbsDecompParams, cbsk)
			assert.Equal(t, m, enc.DecryptGGSW(ctOut)[0])
		}
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchEncrypter.GenEvaluationKeyParallel()
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := benchEncrypter.EncryptLWE(3)
	ctOut := tfhe.NewLWECiphertext(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluater.BootstrapInPlace(ct, ctOut)
	}
}
