package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	fhewParams = xtfhe.ParamsFHEWBinary.Compile()
	fhewEnc    = xtfhe.NewFHEWEncryptor(fhewParams)
	fhewEval   = xtfhe.NewFHEWEvaluator(fhewParams, fhewEnc.GenEvaluationKeyParallel())
)

func TestFHEW(t *testing.T) {
	for _, msg := range []int{0, 1} {
		ct := fhewEnc.EncryptLWE(msg)
		ctOut := fhewEval.BootstrapFunc(ct, func(x int) int { return x ^ 1 })
		assert.Equal(t, fhewEnc.DecryptLWE(ctOut), msg^1)
	}
}
