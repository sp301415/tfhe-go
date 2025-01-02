package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	manyLUTParams = xtfhe.ParamsUint2LUT4.Compile()
	manyLUTCount  = 4
	manyLUTEnc    = tfhe.NewEncryptor(manyLUTParams)
	manyLUTEval   = xtfhe.NewManyLUTEvaluator(manyLUTParams, manyLUTCount, manyLUTEnc.GenEvaluationKeyParallel())
)

func TestManyLUT(t *testing.T) {
	m := int(num.Sqrt(manyLUTParams.MessageModulus()))
	fs := make([]func(int) int, manyLUTCount)
	for i := 0; i < manyLUTCount; i++ {
		j := i
		fs[i] = func(x int) int { return 2*x + j }
	}

	ct := manyLUTEnc.EncryptLWE(m)
	ctOut := manyLUTEval.BootstrapFunc(ct, fs)

	for i := 0; i < manyLUTCount; i++ {
		assert.Equal(t, manyLUTEnc.DecryptLWE(ctOut[i]), fs[i](m)%int(manyLUTParams.MessageModulus()))
	}
}
