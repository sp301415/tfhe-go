package tfhe_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	params = tfhe.ParamsUint3.Compile()
	enc    = tfhe.NewEncryptor(params)
	pkEnc  = tfhe.NewPublicEncryptor(params, enc.GenPublicKey())
	eval   = tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	paramsList = []tfhe.ParametersLiteral[uint64]{
		tfhe.ParamsUint2,
		tfhe.ParamsUint3,
		tfhe.ParamsUint4,
		tfhe.ParamsUint5,
		tfhe.ParamsUint6,
		tfhe.ParamsUint7,
		tfhe.ParamsUint8,
	}
)

func TestParams(t *testing.T) {
	for _, params := range paramsList {
		t.Run(fmt.Sprintf("ParamsUint%v", num.Log2(params.MessageModulus)), func(t *testing.T) {
			assert.NotPanics(t, func() { params.Compile() })
		})
	}
}

func TestEncryptor(t *testing.T) {
	messages := []int{1, 2, 3}
	gadgetParams := params.KeySwitchParameters()

	t.Run("LWE", func(t *testing.T) {
		for _, m := range messages {
			ct := enc.EncryptLWE(m)
			assert.Equal(t, m, enc.DecryptLWE(ct))
		}
	})

	t.Run("PublicLWE", func(t *testing.T) {
		for _, m := range messages {
			ct := pkEnc.EncryptLWE(m)
			assert.Equal(t, m, enc.DecryptLWE(ct))
		}
	})

	t.Run("Lev", func(t *testing.T) {
		for _, m := range messages {
			ct := enc.EncryptLev(m, gadgetParams)
			assert.Equal(t, m, enc.DecryptLev(ct))
		}
	})

	t.Run("GSW", func(t *testing.T) {
		for _, m := range messages {
			ct := enc.EncryptGSW(m, gadgetParams)
			assert.Equal(t, m, enc.DecryptGSW(ct))
		}
	})

	t.Run("GLWE", func(t *testing.T) {
		ct := enc.EncryptGLWE(messages)
		assert.Equal(t, messages, enc.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("PublicGLWE", func(t *testing.T) {
		ct := pkEnc.EncryptGLWE(messages)
		assert.Equal(t, messages, enc.DecryptGLWE(ct)[:len(messages)])
	})

	t.Run("GLev", func(t *testing.T) {
		ct := enc.EncryptGLev(messages, gadgetParams)
		assert.Equal(t, messages, enc.DecryptGLev(ct)[:len(messages)])
	})

	t.Run("GGSW", func(t *testing.T) {
		ct := enc.EncryptGGSW(messages, gadgetParams)
		assert.Equal(t, messages, enc.DecryptGGSW(ct)[:len(messages)])
	})

	t.Run("FourierGLWE", func(t *testing.T) {
		ct := enc.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, enc.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("PublicFourierGLWE", func(t *testing.T) {
		ct := pkEnc.EncryptFourierGLWE(messages)
		assert.Equal(t, messages, enc.DecryptFourierGLWE(ct)[:len(messages)])
	})

	t.Run("FourierGLev", func(t *testing.T) {
		ct := enc.EncryptFourierGLev(messages, gadgetParams)
		assert.Equal(t, messages, enc.DecryptFourierGLev(ct)[:len(messages)])
	})

	t.Run("FourierGGSW", func(t *testing.T) {
		ct := enc.EncryptFourierGGSW(messages, gadgetParams)
		assert.Equal(t, messages, enc.DecryptFourierGGSW(ct)[:len(messages)])
	})
}

func TestEvaluator(t *testing.T) {
	messages := []int{1, 2, 3}

	t.Run("ExternalProduct", func(t *testing.T) {
		ct := enc.EncryptGLWE(messages)

		mul := 2
		ctMul := enc.EncryptFourierGGSW([]int{mul}, params.KeySwitchParameters())

		ctOut := eval.ExternalProductGLWE(ctMul, ct)

		for i, m := range messages {
			assert.Equal(t, mul*m, enc.DecryptGLWE(ctOut)[i])
		}
	})

	t.Run("CMUX", func(t *testing.T) {
		messagesPool := [][]int{messages, vec.Reverse(messages)}

		for _, i := range []int{0, 1} {
			ct0 := enc.EncryptGLWE(messagesPool[0])
			ct1 := enc.EncryptGLWE(messagesPool[1])
			ctGGSW := enc.EncryptFourierGGSW([]int{i}, params.BlindRotateParameters())

			ctOut := eval.CMux(ctGGSW, ct0, ct1)

			assert.Equal(t, messagesPool[i], enc.DecryptGLWE(ctOut)[:len(messages)])
		}
	})

	t.Run("KeySwitch", func(t *testing.T) {
		kskGLWEParams := tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 12,
			Level: 3,
		}.Compile()

		encOut := tfhe.NewEncryptor(params)

		ctLWEIn := enc.EncryptLWE(messages[0])
		ctGLWEIn := enc.EncryptGLWE(messages)

		kskLWE := encOut.GenLWEKeySwitchKey(enc.DefaultLWESecretKey(), params.KeySwitchParameters())
		kskGLWE := encOut.GenGLWEKeySwitchKey(enc.SecretKey.GLWEKey, kskGLWEParams)

		ctLWEOut := eval.KeySwitchLWE(ctLWEIn, kskLWE)
		ctGLWEOut := eval.KeySwitchGLWE(ctGLWEIn, kskGLWE)

		assert.Equal(t, messages[0], encOut.DecryptLWE(ctLWEOut))
		assert.Equal(t, messages, encOut.DecryptGLWE(ctGLWEOut)[:len(messages)])
	})

	t.Run("BootstrapOriginalFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		paramsOriginal := params.Literal().WithBlockSize(1).Compile()
		evalOriginal := tfhe.NewEvaluator(paramsOriginal, eval.EvaluationKey)

		for _, m := range messages {
			ct := enc.EncryptLWE(m)
			ctOut := evalOriginal.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), enc.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapBlockFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		for _, m := range messages {
			ct := enc.EncryptLWE(m)
			ctOut := eval.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), enc.DecryptLWE(ctOut))
		}
	})

	t.Run("BootstrapExtendedFunc", func(t *testing.T) {
		f := func(x int) int { return 2 * x }

		paramsExtended := params.Literal().WithLookUpTableSize(params.PolyDegree() << 1).Compile()
		extendedEvaluator := tfhe.NewEvaluator(paramsExtended, eval.EvaluationKey)

		for _, m := range messages {
			ct := enc.EncryptLWE(m)
			ctOut := extendedEvaluator.BootstrapFunc(ct, f)
			assert.Equal(t, f(m), enc.DecryptLWE(ctOut))
		}
	})
}

func TestMarshal(t *testing.T) {
	var n int64
	var err error
	var buf bytes.Buffer

	t.Run("Parameters", func(t *testing.T) {
		var paramsIn, paramsOut tfhe.Parameters[uint64]

		paramsIn = params
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

		ctIn = enc.EncryptLWE(0)
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

		ctIn = enc.EncryptLev(0, params.KeySwitchParameters())
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

		ctIn = enc.EncryptGSW(0, params.KeySwitchParameters())
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

		ctIn = enc.EncryptGLWE([]int{0})
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

		ctIn = enc.EncryptGLev([]int{0}, params.KeySwitchParameters())
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

		ctIn = enc.EncryptGGSW([]int{0}, params.KeySwitchParameters())
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

		ctIn = enc.EncryptFourierGLWE([]int{0})
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

		ctIn = enc.EncryptFourierGLev([]int{0}, params.KeySwitchParameters())
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

		ctIn = enc.EncryptFourierGGSW([]int{0}, params.KeySwitchParameters())
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

		skIn = enc.GenSecretKey()
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

		pkIn = enc.GenPublicKey()
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

		evkIn = eval.EvaluationKey
		n, err = evkIn.WriteTo(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		n, err = evkOut.ReadFrom(&buf)
		assert.Equal(t, int(n), evkIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, evkIn, evkOut)
	})

	t.Run("GLWEKeySwitchKey", func(t *testing.T) {
		var kskIn, kskOut tfhe.GLWEKeySwitchKey[uint64]

		kskIn = enc.GenGLWEKeySwitchKey(enc.SecretKey.GLWEKey, params.KeySwitchParameters())
		n, err = kskIn.WriteTo(&buf)
		assert.Equal(t, int(n), kskIn.ByteSize())
		assert.NoError(t, err)

		n, err = kskOut.ReadFrom(&buf)
		assert.Equal(t, int(n), kskIn.ByteSize())
		assert.NoError(t, err)

		assert.Equal(t, kskIn, kskOut)
	})
}

func BenchmarkEvaluationKeyGen(b *testing.B) {
	for _, params := range paramsList {
		params := params.Compile()
		enc := tfhe.NewEncryptor(params)

		b.Run(fmt.Sprintf("prec=%v", num.Log2(params.MessageModulus())), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				enc.GenEvaluationKeyParallel()
			}
		})
	}
}

func BenchmarkProgrammableBootstrap(b *testing.B) {
	for _, params := range paramsList {
		params := params.Compile()
		enc := tfhe.NewEncryptor(params)
		eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

		ct := enc.EncryptLWE(0)
		ctOut := ct.Copy()
		lut := eval.GenLookUpTable(func(x int) int { return 2*x + 1 })

		b.Run(fmt.Sprintf("prec=%v", num.Log2(params.MessageModulus())), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.BootstrapLUTAssign(ct, lut, ctOut)
			}
		})
	}
}

func ExampleEncryptor() {
	// Parameters must be compiled before use.
	params := tfhe.ParamsUint4.Compile()

	enc := tfhe.NewEncryptor(params)

	ctLWE := enc.EncryptLWE(4)
	ctGLWE := enc.EncryptGLWE([]int{1, 2, 3, 4})

	// Decrypt Everything!
	fmt.Println(enc.DecryptLWE(ctLWE))
	fmt.Println(enc.DecryptGLWE(ctGLWE)[:4])
	// Output:
	// 4
	// [1 2 3 4]
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
	eval := tfhe.NewEvaluator(params, tfhe.EvaluationKey[uint64]{})

	ctOut := eval.CMux(ctFlag, ct0, ct1)
	fmt.Println(enc.DecryptGLWE(ctOut)[0])
	// Output:
	// 5
}

func ExampleEvaluator_BootstrapFunc() {
	params := tfhe.ParamsUint4.Compile()

	enc := tfhe.NewEncryptor(params)

	ct := enc.EncryptLWE(3)

	eval := tfhe.NewEvaluator(params, enc.GenEvaluationKeyParallel())

	ctOut := eval.BootstrapFunc(ct, func(x int) int { return 2*x + 1 })
	fmt.Println(enc.DecryptLWE(ctOut))
	// Output:
	// 7
}
