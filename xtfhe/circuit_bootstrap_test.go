package xtfhe_test

import (
	"testing"

	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
	"github.com/sp301415/tfhe-go/xtfhe"
	"github.com/stretchr/testify/assert"
)

var (
	cbParams = xtfhe.ParamsBinaryCircuitBootstrapMedium.Compile()
	cbEnc    = tfhe.NewEncryptor(cbParams.BaseParameters())
	cbKeyGen = xtfhe.NewCircuitBootstrapKeyGenerator(cbParams, cbEnc.SecretKey)
	cbEval   = xtfhe.NewCircuitBootstrapper(cbParams, cbEnc.GenEvaluationKeyParallel(), cbKeyGen.GenCircuitBootstrapKey())
)

func TestCircuitBootstrap(t *testing.T) {
	msgGLWE := []int{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0}
	ctGLWE := cbEnc.EncryptGLWE(msgGLWE)

	for _, c := range []int{0, 1} {
		ctLWE := cbEnc.EncryptLWE(c)
		ctFourierGGSW := cbEval.CircuitBootstrap(ctLWE)
		ctGLWEOut := cbEval.ExternalProductGLWE(ctFourierGGSW, ctGLWE)

		msgGLWEOut := cbEnc.DecryptGLWE(ctGLWEOut)[:len(msgGLWE)]
		assert.Equal(t, msgGLWEOut, vec.ScalarMul(msgGLWE, c))
	}
}
