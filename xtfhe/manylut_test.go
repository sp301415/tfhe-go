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
	manyLUTEnc    = tfhe.NewEncryptor(manyLUTParams.BaseParams())
	manyLUTEval   = xtfhe.NewManyLUTEvaluator(manyLUTParams, manyLUTEnc.GenEvalKeyParallel())
)

func TestManyLUT(t *testing.T) {
	m := int(num.Sqrt(manyLUTParams.BaseParams().MessageModulus()))
	fs := make([]func(int) int, manyLUTParams.LUTCount())
	for i := 0; i < manyLUTParams.LUTCount(); i++ {
		j := i
		fs[i] = func(x int) int { return 2*x + j }
	}

	ct := manyLUTEnc.EncryptLWE(m)
	ctOut := manyLUTEval.BootstrapFunc(ct, fs)

	for i := 0; i < manyLUTParams.LUTCount(); i++ {
		assert.Equal(t, manyLUTEnc.DecryptLWE(ctOut[i]), fs[i](m)%int(manyLUTParams.BaseParams().MessageModulus()))
	}
}
