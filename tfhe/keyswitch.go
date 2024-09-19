package tfhe

import "github.com/sp301415/tfhe-go/math/vec"

// KeySwitchLWE switches key of ct.
// Input ciphertext should be of length ksk.InputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchLWE(ct LWECiphertext[T], ksk LWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.KeySwitchLWEAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchLWEAssign switches key of ct and writes it to ctOut.
// Input ciphertext should be of length ksk.InputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchLWEAssign(ct LWECiphertext[T], ksk LWEKeySwitchKey[T], ctOut LWECiphertext[T]) {
	scalarDecomposed := e.Decomposer.ScalarDecomposedBuffer(ksk.GadgetParameters)

	e.Decomposer.DecomposeScalarAssign(ct.Value[1], ksk.GadgetParameters, scalarDecomposed)
	e.ScalarMulLWEAssign(ksk.Value[0].Value[0], scalarDecomposed[0], e.buffer.ctProdLWE)
	for j := 1; j < ksk.GadgetParameters.level; j++ {
		e.ScalarMulAddLWEAssign(ksk.Value[0].Value[j], scalarDecomposed[j], e.buffer.ctProdLWE)
	}

	for i := 1; i < ksk.InputLWEDimension(); i++ {
		e.Decomposer.DecomposeScalarAssign(ct.Value[i+1], ksk.GadgetParameters, scalarDecomposed)
		for j := 0; j < ksk.GadgetParameters.level; j++ {
			e.ScalarMulAddLWEAssign(ksk.Value[i].Value[j], scalarDecomposed[j], e.buffer.ctProdLWE)
		}
	}

	ctOut.Value[0] = ct.Value[0] + e.buffer.ctProdLWE.Value[0]
	vec.CopyAssign(e.buffer.ctProdLWE.Value[1:], ctOut.Value[1:])
}

// KeySwitchGLWE switches key of ct.
// Input ciphertext should be of length ksk.InputGLWERank + 1.
func (e *Evaluator[T]) KeySwitchGLWE(ct GLWECiphertext[T], ksk GLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.KeySwitchGLWEAssign(ct, ksk, ctOut)
	return ctOut
}

// KeySwitchGLWEAssign switches key of ct and writes it to ctOut.
// Input ciphertext should be of length ksk.InputGLWERank + 1.
func (e *Evaluator[T]) KeySwitchGLWEAssign(ct GLWECiphertext[T], ksk GLWEKeySwitchKey[T], ctOut GLWECiphertext[T]) {
	fourierDecomposed := e.Decomposer.PolyFourierDecomposedBuffer(ksk.GadgetParameters)

	e.Decomposer.FourierDecomposePolyAssign(ct.Value[1], ksk.GadgetParameters, fourierDecomposed)
	e.FourierPolyMulFourierGLWEAssign(ksk.Value[0].Value[0], fourierDecomposed[0], e.buffer.ctProdFourierGLWE)
	for j := 1; j < ksk.GadgetParameters.level; j++ {
		e.FourierPolyMulAddFourierGLWEAssign(ksk.Value[0].Value[j], fourierDecomposed[j], e.buffer.ctProdFourierGLWE)
	}

	for i := 1; i < ksk.InputGLWERank(); i++ {
		e.Decomposer.FourierDecomposePolyAssign(ct.Value[i+1], ksk.GadgetParameters, fourierDecomposed)
		for j := 0; j < ksk.GadgetParameters.level; j++ {
			e.FourierPolyMulAddFourierGLWEAssign(ksk.Value[i].Value[j], fourierDecomposed[j], e.buffer.ctProdFourierGLWE)
		}
	}

	ctOut.Value[0].CopyFrom(ct.Value[0])
	e.PolyEvaluator.ToPolyAddAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[0], ctOut.Value[0])
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.PolyEvaluator.ToPolyAssignUnsafe(e.buffer.ctProdFourierGLWE.Value[i+1], ctOut.Value[i+1])
	}
}
