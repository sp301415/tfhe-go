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
// Use [*CircuitBootstrapper.ShallowCopy] to get a safe copy.
type CircuitBootstrapper[T tfhe.TorusInt] struct {
	// Evaluator is an embedded Evaluator for this CircuitBootstrapper.
	*ManyLUTEvaluator[T]
	// BFVEvaluator is an embedded BFVEvaluator for this CircuitBootstrapper.
	*BFVEvaluator[T]
	// Decomposer is a Decomposer for this CircuitBootstrapper.
	Decomposer *tfhe.Decomposer[T]

	// Parameters is the parameters for this CircuitBootstrapper.
	Parameters CircuitBootstrapParameters[T]

	// EvaluationKey is a circuit bootstrapping key for this CircuitBootstrapper.
	EvaluationKey CircuitBootstrapKey[T]

	buffer circuitBootstrapBuffer[T]
}

// circuitBootstrapBuffer is a buffer for CircuitBootstrapper.
type circuitBootstrapBuffer[T tfhe.TorusInt] struct {
	// fs are the functions for LUT.
	fs []func(x int) T
	// lut is an empty lut.
	lut tfhe.LookUpTable[T]

	// ctFourierDecomposed are buffer for decomposed ciphertexts during scheme switching.
	ctFourierDecomposed [][]poly.FourierPoly

	// ctKeySwitch is a key-switched LWE ciphertext.
	ctKeySwitch tfhe.LWECiphertext[T]
	// ctPack is the permuted ciphertext for trace.
	ctPack tfhe.GLWECiphertext[T]
	// ctRotate is a temporary GLWE ciphertext after Blind Rotation.
	ctRotate tfhe.GLWECiphertext[T]
	// ctFourierGLWEOut is a temporary Fourier transformed GLWE ciphertext.
	ctFourierGLWEOut tfhe.FourierGLWECiphertext[T]
	// ctGGSWOut is the output GGSW ciphertext of circuit bootstrapping.
	ctGGSWOut tfhe.GGSWCiphertext[T]
}

// NewCircuitBootstrapper creates a new CircuitBootstrapper.
// For circuit bootstrapping, we need relin key and galois keys for LWE to GLWE.
func NewCircuitBootstrapper[T tfhe.TorusInt](params CircuitBootstrapParameters[T], evk tfhe.EvaluationKey[T], cbk CircuitBootstrapKey[T]) *CircuitBootstrapper[T] {
	decomposer := tfhe.NewDecomposer[T](params.BaseParameters().PolyDegree())
	decomposer.PolyDecomposedBuffer(params.schemeSwitchParameters)
	decomposer.PolyFourierDecomposedBuffer(params.schemeSwitchParameters)

	return &CircuitBootstrapper[T]{
		ManyLUTEvaluator: NewManyLUTEvaluator(params.manyLUTParameters, evk),
		BFVEvaluator:     NewBFVEvaluator(params.BaseParameters(), BFVEvaluationKey[T]{GaloisKeys: cbk.TraceKeys}),
		Decomposer:       decomposer,

		Parameters:    params,
		EvaluationKey: cbk,

		buffer: newCircuitBootstrapBuffer(params),
	}
}

// newCircuitBootstrapBuffer creates a new circuitBootstrapBuffer.
func newCircuitBootstrapBuffer[T tfhe.TorusInt](params CircuitBootstrapParameters[T]) circuitBootstrapBuffer[T] {
	fs := make([]func(x int) T, params.manyLUTParameters.lutCount)
	for i := 0; i < params.manyLUTParameters.lutCount; i++ {
		fs[i] = func(x int) T { return 0 }
	}

	ctFourierDecomposed := make([][]poly.FourierPoly, params.BaseParameters().GLWERank()+1)
	for i := 0; i < params.BaseParameters().GLWERank()+1; i++ {
		ctFourierDecomposed[i] = make([]poly.FourierPoly, params.schemeSwitchParameters.Level())
		for j := 0; j < params.schemeSwitchParameters.Level(); j++ {
			ctFourierDecomposed[i][j] = poly.NewFourierPoly(params.BaseParameters().PolyDegree())
		}
	}

	return circuitBootstrapBuffer[T]{
		fs:  fs,
		lut: tfhe.NewLookUpTable(params.BaseParameters()),

		ctFourierDecomposed: ctFourierDecomposed,

		ctKeySwitch:      tfhe.NewLWECiphertextCustom[T](params.BaseParameters().LWEDimension()),
		ctPack:           tfhe.NewGLWECiphertext(params.BaseParameters()),
		ctRotate:         tfhe.NewGLWECiphertext(params.BaseParameters()),
		ctFourierGLWEOut: tfhe.NewFourierGLWECiphertext(params.BaseParameters()),
		ctGGSWOut:        tfhe.NewGGSWCiphertext(params.BaseParameters(), params.outputParameters),
	}
}

// ShallowCopy creates a shallow copy of this CircuitBootstrapper.
// Returned CircuitBootstrapper is safe for concurrent use.
func (e *CircuitBootstrapper[T]) ShallowCopy() *CircuitBootstrapper[T] {
	return &CircuitBootstrapper[T]{
		ManyLUTEvaluator: e.ManyLUTEvaluator.ShallowCopy(),
		BFVEvaluator:     e.BFVEvaluator.ShallowCopy(),

		Parameters:    e.Parameters,
		EvaluationKey: e.EvaluationKey,

		buffer: newCircuitBootstrapBuffer(e.Parameters),
	}
}

// CircuitBootstrap performs Circuit Bootstrapping and returns the result.
func (e *CircuitBootstrapper[T]) CircuitBootstrap(ct tfhe.LWECiphertext[T]) tfhe.FourierGGSWCiphertext[T] {
	ctOut := tfhe.NewFourierGGSWCiphertext(e.Parameters.BaseParameters(), e.Parameters.outputParameters)
	e.CircuitBootstrapAssign(ct, ctOut)
	return ctOut
}

// CircuitBootstrapAssign performs Circuit Bootstrapping and writes the result to ctOut.
// The gadget parameters of ctOut should be equal to the output parameters of CircuitBootstrapper.
func (e *CircuitBootstrapper[T]) CircuitBootstrapAssign(ct tfhe.LWECiphertext[T], ctOut tfhe.FourierGGSWCiphertext[T]) {
	polyDecomposed := e.Decomposer.PolyDecomposedBuffer(e.Parameters.schemeSwitchParameters)

	for i := 0; i < e.Parameters.outputParameters.Level(); i += e.ManyLUTEvaluator.Parameters.lutCount {
		start := i
		end := num.Min(i+e.ManyLUTEvaluator.Parameters.lutCount, e.Parameters.outputParameters.Level())

		for j, jj := start, 0; j < end; j, jj = j+1, jj+1 {
			logBase := ctOut.GadgetParameters.LogBaseQ(j)
			e.buffer.fs[jj] = func(x int) T {
				return T(x) << logBase
			}
		}

		e.GenLookUpTableFullAssign(e.buffer.fs, e.buffer.lut)
		switch e.Parameters.BaseParameters().BootstrapOrder() {
		case tfhe.OrderBlindRotateKeySwitch:
			e.BlindRotateAssign(ct, e.buffer.lut, e.buffer.ctRotate)
		case tfhe.OrderKeySwitchBlindRotate:
			e.KeySwitchForBootstrapAssign(ct, e.buffer.ctKeySwitch)
			e.BlindRotateAssign(e.buffer.ctKeySwitch, e.buffer.lut, e.buffer.ctRotate)
		}

		for j := 0; j < e.Parameters.BaseParameters().GLWERank()+1; j++ {
			for k := 0; k < e.Parameters.BaseParameters().PolyDegree(); k++ {
				e.buffer.ctRotate.Value[j].Coeffs[k] = num.DivRoundBits(e.buffer.ctRotate.Value[j].Coeffs[k], e.Parameters.BaseParameters().LogPolyDegree())
			}
		}

		for j, jj := start, 0; j < end; j, jj = j+1, jj+1 {
			e.MonomialMulGLWEAssign(e.buffer.ctRotate, -jj, e.buffer.ctGGSWOut.Value[0].Value[j])
			for k := 0; k < e.Parameters.BaseParameters().LogPolyDegree(); k++ {
				e.PermuteAssign(e.buffer.ctGGSWOut.Value[0].Value[j], 1<<(e.Parameters.BaseParameters().LogPolyDegree()-k)+1, e.buffer.ctPack)
				e.BaseEvaluator.AddGLWEAssign(e.buffer.ctGGSWOut.Value[0].Value[j], e.buffer.ctPack, e.buffer.ctGGSWOut.Value[0].Value[j])
			}

			for k := 0; k < e.Parameters.BaseParameters().GLWERank()+1; k++ {
				e.Decomposer.DecomposePolyAssign(e.buffer.ctGGSWOut.Value[0].Value[j].Value[k], e.Parameters.schemeSwitchParameters, polyDecomposed)
				for l := 0; l < e.Parameters.schemeSwitchParameters.Level(); l++ {
					e.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[l], e.buffer.ctFourierDecomposed[k][l])
				}
			}

			for k := 0; k < e.Parameters.BaseParameters().GLWERank(); k++ {
				e.ExternalProductFourierDecomposedFourierGLWEAssign(e.EvaluationKey.SchemeSwitchKey[k], e.buffer.ctFourierDecomposed, e.buffer.ctFourierGLWEOut)
				for l := 0; l < e.Parameters.BaseParameters().GLWERank()+1; l++ {
					e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctFourierGLWEOut.Value[l], e.buffer.ctGGSWOut.Value[k+1].Value[j].Value[l])
				}
			}
		}
	}

	e.ToFourierGGSWCiphertextAssign(e.buffer.ctGGSWOut, ctOut)
}
