package tfhe_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/stretchr/testify/assert"
)

var (
	paramsBinary = tfhe.ParamsBinary.Compile()
	encBinary    = tfhe.NewBinaryEncryptor(paramsBinary)
	evalBinary   = tfhe.NewBinaryEvaluator(paramsBinary, encBinary.GenEvalKeyParallel())
)

func TestBinaryParams(t *testing.T) {
	t.Run("Compile/ParamsBinary", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinary.Compile() })
	})

	t.Run("Compile/ParamsBinaryCompact", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinaryCompact.Compile() })
	})

	t.Run("Compile/ParamsBinaryOriginal", func(t *testing.T) {
		assert.NotPanics(t, func() { tfhe.ParamsBinaryOriginal.Compile() })
	})

	t.Run("FailureProbability/ParamsBinary", func(t *testing.T) {
		params := tfhe.ParamsBinary.Compile()

		msStdDev := params.EstimateModSwitchStdDev()
		brStdDev := params.EstimateBlindRotateStdDev()
		ksStdDev := params.EstimateDefaultKeySwitchStdDev()
		maxErrorStdDev := math.Sqrt(msStdDev*msStdDev + 4*brStdDev*brStdDev + 4*ksStdDev*ksStdDev)

		bound := math.Exp2(float64(params.LogQ())) / 16
		failureProbability := math.Erfc(bound / (math.Sqrt2 * maxErrorStdDev))
		assert.LessOrEqual(t, math.Log2(failureProbability), -64.0)
	})

	t.Run("FailureProbability/ParamsBinaryCompact", func(t *testing.T) {
		params := tfhe.ParamsBinaryCompact.Compile()

		msStdDev := params.EstimateModSwitchStdDev()
		ksStdDev := params.EstimateDefaultKeySwitchStdDev()
		brStdDev := params.EstimateBlindRotateStdDev()
		maxErrorStdDev := math.Sqrt(msStdDev*msStdDev + ksStdDev*ksStdDev + 4*brStdDev*brStdDev)

		bound := math.Exp2(float64(params.LogQ())) / 16
		failureProbability := math.Erfc(bound / (math.Sqrt2 * maxErrorStdDev))
		assert.LessOrEqual(t, math.Log2(failureProbability), -64.0)
	})
}

func TestBinaryEvaluator(t *testing.T) {
	tests := []struct {
		pt0 bool
		pt1 bool
		ct0 tfhe.LWECiphertext[uint32]
		ct1 tfhe.LWECiphertext[uint32]
	}{
		{true, true, encBinary.EncryptLWEBool(true), encBinary.EncryptLWEBool(true)},
		{true, false, encBinary.EncryptLWEBool(true), encBinary.EncryptLWEBool(false)},
		{false, true, encBinary.EncryptLWEBool(false), encBinary.EncryptLWEBool(true)},
		{false, false, encBinary.EncryptLWEBool(false), encBinary.EncryptLWEBool(false)},
	}

	t.Run("AND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, encBinary.DecryptLWEBool(evalBinary.AND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NAND", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 && tc.pt1), encBinary.DecryptLWEBool(evalBinary.NAND(tc.ct0, tc.ct1)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 || tc.pt1, encBinary.DecryptLWEBool(evalBinary.OR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("NOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, !(tc.pt0 || tc.pt1), encBinary.DecryptLWEBool(evalBinary.NOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 != tc.pt1, encBinary.DecryptLWEBool(evalBinary.XOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("XNOR", func(t *testing.T) {
		for _, tc := range tests {
			assert.Equal(t, tc.pt0 == tc.pt1, encBinary.DecryptLWEBool(evalBinary.XNOR(tc.ct0, tc.ct1)))
		}
	})

	t.Run("Bits", func(t *testing.T) {
		msg0, msg1 := 0b01, 0b10
		ct0 := encBinary.EncryptLWEBits(msg0, 4)
		ct1 := encBinary.EncryptLWEBits(msg1, 4)

		ctOut := encBinary.EncryptLWEBits(0, 4)
		for i := range ctOut {
			evalBinary.XORTo(ctOut[i], ct0[i], ct1[i])
		}

		assert.Equal(t, encBinary.DecryptLWEBits(ctOut), msg0^msg1)
	})

	t.Run("BootstrapOriginal", func(t *testing.T) {
		paramsBinaryOriginal := paramsBinary.Literal().WithBlockSize(1).Compile()

		originalEncryptor := tfhe.NewBinaryEncryptorWithKey(paramsBinaryOriginal, encBinary.Encryptor.SecretKey)
		originalEvaluator := tfhe.NewBinaryEvaluator(paramsBinaryOriginal, evalBinary.Evaluator.EvalKey)

		for _, tc := range tests {
			assert.Equal(t, tc.pt0 && tc.pt1, originalEncryptor.DecryptLWEBool(originalEvaluator.AND(tc.ct0, tc.ct1)))
		}
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := encBinary.EncryptLWEBool(true)
	ct1 := encBinary.EncryptLWEBool(false)
	ctOut := tfhe.NewLWECiphertext(paramsBinary)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		evalBinary.ANDTo(ctOut, ct0, ct1)
	}
}

func ExampleBinaryEvaluator() {
	params := tfhe.ParamsBinary.Compile()

	enc := tfhe.NewBinaryEncryptor(params)

	bits := 16
	ct0 := enc.EncryptLWEBits(3, bits)
	ct1 := enc.EncryptLWEBits(3, bits)

	eval := tfhe.NewBinaryEvaluator(params, enc.GenEvalKeyParallel())

	ctXNOR := tfhe.NewLWECiphertext(params)
	ctOut := eval.XNOR(ct0[0], ct1[0])
	for i := 1; i < bits; i++ {
		eval.XNORTo(ctXNOR, ct0[i], ct1[i])
		eval.ANDTo(ctOut, ctXNOR, ctOut)
	}

	fmt.Println(enc.DecryptLWEBool(ctOut))
	// Output:
	// true
}
