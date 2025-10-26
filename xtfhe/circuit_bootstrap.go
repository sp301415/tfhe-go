package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// CircuitBootstrapper wraps around [tfhe.Evaluator], and implements Circuit Bootstrapping Algorithm.
// For more details, see https://eprint.iacr.org/2024/1318.
//
// CircuitBootstrapper is not safe for concurrent use.
// Use [*CircuitBootstrapper.SafeCopy] to get a safe copy.
type CircuitBootstrapper[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this CircuitBootstrapper.
	*ManyLUTEvaluator[T]
	// BFVEvaluator is an embedded BFVEvaluator for this CircuitBootstrapper.
	*BFVEvaluator[T]
	// Decomposer is a Decomposer for this CircuitBootstrapper.
	Decomposer *tfhe.Decomposer[T]

	// Params is the parameters for this CircuitBootstrapper.
	Params CircuitBootstrapParameters[T]

	// EvalKey is a circuit bootstrapping key for this CircuitBootstrapper.
	EvalKey CircuitBootstrapKey[T]

	buf circuitBootstrapBuffer[T]
}

// circuitBootstrapBuffer is a buffer for CircuitBootstrapper.
type circuitBootstrapBuffer[T tfhe.TorusInt] struct {
	// fs are the functions for LUT.
	fs []func(x int) T
	// lut is an empty lut.
	lut tfhe.LookUpTable[T]

	// fctDcmp are buffer for decomposed ciphertexts during scheme switching.
	fctDcmp [][]poly.FFTPoly

	// ctKeySwitch is a key-switched LWE ciphertext.
	ctKeySwitch tfhe.LWECiphertext[T]
	// ctPack is the permuted ciphertext for trace.
	ctPack tfhe.GLWECiphertext[T]
	// ctRotate is a temporary GLWE ciphertext after Blind Rotation.
	ctRotate tfhe.GLWECiphertext[T]
	// ctFFTGLWEOut is a temporary Fourier transformed GLWE ciphertext.
	ctFFTGLWEOut tfhe.FFTGLWECiphertext[T]
	// ctGGSWOut is the output GGSW ciphertext of circuit bootstrapping.
	ctGGSWOut tfhe.GGSWCiphertext[T]
}

// NewCircuitBootstrapper creates a new CircuitBootstrapper.
// For circuit bootstrapping, we need relin key and galois keys for LWE to GLWE.
func NewCircuitBootstrapper[T tfhe.TorusInt](params CircuitBootstrapParameters[T], evk tfhe.EvaluationKey[T], cbk CircuitBootstrapKey[T]) *CircuitBootstrapper[T] {
	decomposer := tfhe.NewDecomposer[T](params.Params().PolyRank())
	decomposer.PolyBuffer(params.schemeSwitchParameters)
	decomposer.FFTPolyBuffer(params.schemeSwitchParameters)

	return &CircuitBootstrapper[T]{
		ManyLUTEvaluator: NewManyLUTEvaluator(params.manyLUTParameters, evk),
		BFVEvaluator:     NewBFVEvaluator(params.Params(), BFVEvaluationKey[T]{GaloisKeys: cbk.TraceKeys}),
		Decomposer:       decomposer,

		Params:  params,
		EvalKey: cbk,

		buf: newCircuitBootstrapBuffer(params),
	}
}

// newCircuitBootstrapBuffer creates a new circuitBootstrapBuffer.
func newCircuitBootstrapBuffer[T tfhe.TorusInt](params CircuitBootstrapParameters[T]) circuitBootstrapBuffer[T] {
	fs := make([]func(x int) T, params.manyLUTParameters.lutCount)
	for i := 0; i < params.manyLUTParameters.lutCount; i++ {
		fs[i] = func(x int) T { return 0 }
	}

	fctDcmp := make([][]poly.FFTPoly, params.Params().GLWERank()+1)
	for i := 0; i < params.Params().GLWERank()+1; i++ {
		fctDcmp[i] = make([]poly.FFTPoly, params.schemeSwitchParameters.Level())
		for j := 0; j < params.schemeSwitchParameters.Level(); j++ {
			fctDcmp[i][j] = poly.NewFFTPoly(params.Params().PolyRank())
		}
	}

	return circuitBootstrapBuffer[T]{
		fs:  fs,
		lut: tfhe.NewLUT(params.Params()),

		fctDcmp: fctDcmp,

		ctKeySwitch:  tfhe.NewLWECiphertextCustom[T](params.Params().LWEDimension()),
		ctPack:       tfhe.NewGLWECiphertext(params.Params()),
		ctRotate:     tfhe.NewGLWECiphertext(params.Params()),
		ctFFTGLWEOut: tfhe.NewFFTGLWECiphertext(params.Params()),
		ctGGSWOut:    tfhe.NewGGSWCiphertext(params.Params(), params.outputParameters),
	}
}

// SafeCopy creates a shallow copy of this CircuitBootstrapper.
// Returned CircuitBootstrapper is safe for concurrent use.
func (e *CircuitBootstrapper[T]) SafeCopy() *CircuitBootstrapper[T] {
	return &CircuitBootstrapper[T]{
		ManyLUTEvaluator: e.ManyLUTEvaluator.SafeCopy(),
		BFVEvaluator:     e.BFVEvaluator.SafeCopy(),

		Params:  e.Params,
		EvalKey: e.EvalKey,

		buf: newCircuitBootstrapBuffer(e.Params),
	}
}

// CircuitBootstrap performs Circuit Bootstrapping and returns the result.
func (e *CircuitBootstrapper[T]) CircuitBootstrap(ct tfhe.LWECiphertext[T]) tfhe.FFTGGSWCiphertext[T] {
	ctOut := tfhe.NewFFTGGSWCiphertext(e.Params.Params(), e.Params.outputParameters)
	e.CircuitBootstrapTo(ctOut, ct)
	return ctOut
}

// CircuitBootstrapTo performs Circuit Bootstrapping and writes the result to ctOut.
// The gadget parameters of ctOut should be equal to the output parameters of CircuitBootstrapper.
func (e *CircuitBootstrapper[T]) CircuitBootstrapTo(ctOut tfhe.FFTGGSWCiphertext[T], ct tfhe.LWECiphertext[T]) {
	pDcmp := e.Decomposer.PolyBuffer(e.Params.schemeSwitchParameters)

	for i := 0; i < e.Params.outputParameters.Level(); i += e.ManyLUTEvaluator.Params.lutCount {
		start := i
		end := num.Min(i+e.ManyLUTEvaluator.Params.lutCount, e.Params.outputParameters.Level())

		for j, jj := start, 0; j < end; j, jj = j+1, jj+1 {
			logBase := ctOut.GadgetParams.LogBaseQ(j)
			e.buf.fs[jj] = func(x int) T {
				return T(x) << logBase
			}
		}

		e.GenLookUpTableFullTo(e.buf.lut, e.buf.fs)
		switch e.Params.Params().BootstrapOrder() {
		case tfhe.OrderBlindRotateKeySwitch:
			e.BlindRotateTo(e.buf.ctRotate, ct, e.buf.lut)
		case tfhe.OrderKeySwitchBlindRotate:
			e.DefaultKeySwitchTo(e.buf.ctKeySwitch, ct)
			e.BlindRotateTo(e.buf.ctRotate, e.buf.ctKeySwitch, e.buf.lut)
		}

		for j := 0; j < e.Params.Params().GLWERank()+1; j++ {
			for k := 0; k < e.Params.Params().PolyRank(); k++ {
				e.buf.ctRotate.Value[j].Coeffs[k] = num.DivRoundBits(e.buf.ctRotate.Value[j].Coeffs[k], e.Params.Params().LogPolyRank())
			}
		}

		for j, jj := start, 0; j < end; j, jj = j+1, jj+1 {
			e.MonomialMulGLWETo(e.buf.ctGGSWOut.Value[0].Value[j], e.buf.ctRotate, -jj)
			for k := 0; k < e.Params.Params().LogPolyRank(); k++ {
				e.PermuteTo(e.buf.ctPack, e.buf.ctGGSWOut.Value[0].Value[j], 1<<(e.Params.Params().LogPolyRank()-k)+1)
				e.AddGLWETo(e.buf.ctGGSWOut.Value[0].Value[j], e.buf.ctGGSWOut.Value[0].Value[j], e.buf.ctPack)
			}

			for k := 0; k < e.Params.Params().GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyTo(pDcmp, e.buf.ctGGSWOut.Value[0].Value[j].Value[k], e.Params.schemeSwitchParameters)
				for l := 0; l < e.Params.schemeSwitchParameters.Level(); l++ {
					e.PolyEvaluator.FFTTo(e.buf.fctDcmp[k][l], pDcmp[l])
				}
			}

			for k := 0; k < e.Params.Params().GLWERank(); k++ {
				e.ExternalProdFFTGLWETo(e.buf.ctFFTGLWEOut, e.EvalKey.SchemeSwitchKey[k], e.buf.fctDcmp)
				for l := 0; l < e.Params.Params().GLWERank()+1; l++ {
					e.PolyEvaluator.InvFFTToUnsafe(e.buf.ctGGSWOut.Value[k+1].Value[j].Value[l], e.buf.ctFFTGLWEOut.Value[l])
				}
			}
		}
	}

	e.FFTGGSWCiphertextTo(ctOut, e.buf.ctGGSWOut)
}
