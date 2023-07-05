package tfheb_test

import (
	"testing"

	"github.com/sp301415/tfhe/tfhe"
	"github.com/sp301415/tfhe/tfheb"
	"github.com/stretchr/testify/assert"
)

var (
	testParams = tfheb.ParamsBoolean.Compile()
	enc        = tfhe.NewEncrypter(testParams)
	eval       = tfheb.NewEvaluater(testParams, enc.GenEvaluationKeyParallel())
)

func i2b(x int) bool {
	return x != 0
}

func TestEvaluater(t *testing.T) {
	ciphertexts := make(map[[2]int][2]tfhe.LWECiphertext[uint32], 4)
	for i := 0; i <= 1; i++ {
		for j := 0; j <= 1; j++ {
			ciphertexts[[2]int{i, j}] = [2]tfhe.LWECiphertext[uint32]{
				enc.EncryptLWE(i),
				enc.EncryptLWE(j),
			}
		}
	}

	t.Run("NOT", func(t *testing.T) {
		for pt, ct := range ciphertexts {
			ctOut := eval.NOT(ct[0])
			assert.Equal(t, !i2b(pt[0]), i2b(enc.DecryptLWE(ctOut)))
		}
	})

	t.Run("AND", func(t *testing.T) {
		for pt, ct := range ciphertexts {
			ctOut := eval.AND(ct[0], ct[1])
			assert.Equal(t, i2b(pt[0]) && i2b(pt[1]), i2b(enc.DecryptLWE(ctOut)))
		}
	})

	t.Run("OR", func(t *testing.T) {
		for pt, ct := range ciphertexts {
			ctOut := eval.OR(ct[0], ct[1])
			assert.Equal(t, i2b(pt[0]) || i2b(pt[1]), i2b(enc.DecryptLWE(ctOut)))
		}
	})

	t.Run("XOR", func(t *testing.T) {
		for pt, ct := range ciphertexts {
			ctOut := eval.XOR(ct[0], ct[1])
			assert.Equal(t, i2b(pt[0]) != i2b(pt[1]), i2b(enc.DecryptLWE(ctOut)))
		}
	})
}

func BenchmarkGateBootstrap(b *testing.B) {
	ct0 := enc.EncryptLWE(1)
	ct1 := enc.EncryptLWE(1)
	ctOut := tfhe.NewLWECiphertext(testParams)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eval.ANDInPlace(ct0, ct1, ctOut)
	}
}

func BenchmarkBooleanBootstrap(b *testing.B) {
	ct := enc.EncryptLWE(1)
	lut := eval.GenLookUpTable(func(x int) int { return x })
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		eval.BootstrapLUTInPlace(ct, lut, ct)
	}
}
