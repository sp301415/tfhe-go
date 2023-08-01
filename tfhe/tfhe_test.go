package tfhe_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/sp301415/tfhe/math/vec"
	"github.com/sp301415/tfhe/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	testParams  = tfhe.ParamsUint3.Compile()
	benchParams = tfhe.ParamsUint6.Compile()

	testEncryptor = tfhe.NewEncryptor(testParams)
	testEvaluator = tfhe.NewEvaluator(testParams, testEncryptor.GenEvaluationKeyParallel())

	benchEncryptor = tfhe.NewEncryptor(benchParams)
	benchEvaluator = tfhe.NewEvaluator(benchParams, benchEncryptor.GenEvaluationKeyParallel())
)

func TestEncryptor(t *testing.T) {
	messages := []int{1, 2, 3}
	decompParams := testParams.KeySwitchParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptLWE(m)
			assert.Equal(t, m, testEncryptor.DecryptLWE(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptLev(m, decompParams)
			assert.Equal(t, m, testEncryptor.DecryptLev(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := testEncryptor.EncryptGSW(m, decompParams)
			assert.Equal(t, m, testEncryptor.DecryptGSW(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := testEncryptor.EncryptGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := testEncryptor.EncryptGLev(messages, decompParams)
		assert.Equal(t, messages, testEncryptor.DecryptGLev(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := testEncryptor.EncryptGGSW(messages, decompParams)
		assert.Equal(t, messages, testEncryptor.DecryptGGSW(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierGLev", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGLev(messages, decompParams)
		assert.Equal(t, messages, testEncryptor.DecryptFourierGLev(ct)[:len(messages)])
	})

	t.Run("FourierGGSW", func(t *testing.T) {
		ct := testEncryptor.EncryptFourierGGSW(messages, decompParams)
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

	t.Run("BootstrapFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := testEncryptor.EncryptLWE(m)
			ctOut := testEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), testEncryptor.DecryptLWE(ctOut))
		}
	})

	t.Run("PrivateFunctionalLWEKeySwitch", func(t *testing.T) {
		sum := func(in []uint64) uint64 {
			return in[0] + in[1]
		}
		pfksk := testEncryptor.GenPrivateFunctionalLWEKeySwitchKeyParallel(2, sum, testParams.KeySwitchParameters())

		ct0 := testEncryptor.EncryptLWE(messages[0])
		ct1 := testEncryptor.EncryptLWE(messages[1])
		ctOut := testEvaluator.PrivateFunctionalLWEKeySwitch([]tfhe.LWECiphertext[uint64]{ct0, ct1}, pfksk)

		assert.Equal(t, messages[0]+messages[1], testEncryptor.DecryptLWE(ctOut))
	})

	t.Run("PublicFunctionalLWEKeySwitch", func(t *testing.T) {
		pfksk := testEncryptor.GenPublicFunctionalGLWEKeySwitchKeyParallel(testParams.KeySwitchParameters())

		ct0 := testEncryptor.EncryptLWE(messages[0])
		ct1 := testEncryptor.EncryptLWE(messages[1])
		ctOut := testEvaluator.PackingPublicFunctionalKeySwitch([]tfhe.LWECiphertext[uint64]{ct0, ct1}, pfksk)

		assert.Equal(t, []int{messages[0], messages[1]}, testEncryptor.DecryptGLWE(ctOut)[:2])
	})

	t.Run("CircuitBootstrap", func(t *testing.T) {
		cbsParams := tfhe.ParametersLiteral[uint64]{
			LWEDimension:  10,
			GLWEDimension: 2,
			PolyDegree:    512,

			LWEStdDev:  math.Exp2(-60),
			GLWEStdDev: math.Exp2(-60),
			BlockSize:  1,

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

		enc := tfhe.NewEncryptor(cbsParams)
		eval := tfhe.NewEvaluator(cbsParams, enc.GenEvaluationKeyParallel())

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
		benchEncryptor.GenEvaluationKeyParallel()
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := benchEncryptor.EncryptLWE(3)
	ctOut := tfhe.NewLWECiphertext(benchParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchEvaluator.BootstrapAssign(ct, ctOut)
	}
}

func ExampleEncryptor() {
	params := tfhe.ParamsUint4.Compile() // Parameters should be compiled before use.

	enc := tfhe.NewEncryptor(params) // Set up Encryptor.

	ctLWE := enc.EncryptLWE(4)
	ctGLWE := enc.EncryptGLWE([]int{1, 2, 3, 4})

	// Decrypt Everything!
	fmt.Println(enc.DecryptLWE(ctLWE))       // 4
	fmt.Println(enc.DecryptGLWE(ctGLWE)[:4]) // [1, 2, 3, 4]
}

func ExampleEvaluator_CMux() {
	params := tfhe.ParamsUint4.Compile()
	decompParams := tfhe.DecompositionParametersLiteral[uint64]{
		Base:  1 << 3,
		Level: 6,
	}.Compile()

	enc := tfhe.NewEncryptor(params)

	ct0 := enc.EncryptGLWE([]int{2})
	ct1 := enc.EncryptGLWE([]int{5})
	ctFlag := enc.EncryptFourierGGSW([]int{1}, decompParams)

	// We don't need evaluation key for CMUX,
	// so we can just supply empty key.
	eval := tfhe.NewEvaluator(params, tfhe.EvaluationKey[uint64]{})

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
