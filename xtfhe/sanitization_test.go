package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	sanitizationParams = xtfhe.ParamsSanitizeBinary.Compile()
	sanitizationEnc    = tfhe.NewEncryptor(sanitizationParams.BaseParams())
	sanitizationEval   = xtfhe.NewSanitizer(sanitizationParams, sanitizationEnc.GenPublicKey(), sanitizationEnc.GenEvalKeyParallel())
)

func TestSanitization(t *testing.T) {
	for _, m := range []int{0, 1} {
		ct := sanitizationEnc.EncryptLWE(m)
		ctOut := sanitizationEval.SanitizeFunc(ct, func(i int) int { return i })

		assert.Equal(t, sanitizationEnc.DecryptLWE(ctOut), m)
	}
}
