package tfhe

// KeySwitchLWE switches key of ct.
// Input ciphertext should be of length ksk.InputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchLWE(ct LWECiphertext[T], ksk LWEKeySwitchKey[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.KeySwitchLWETo(ctOut, ct, ksk)
	return ctOut
}

// KeySwitchLWETo switches key of ct and writes it to ctOut.
// Input ciphertext should be of length ksk.InputLWEDimension + 1.
func (e *Evaluator[T]) KeySwitchLWETo(ctOut, ct LWECiphertext[T], ksk LWEKeySwitchKey[T]) {
	cDcmp := e.Decomposer.ScalarBuffer(ksk.GadgetParams)

	e.Decomposer.DecomposeScalarTo(cDcmp, ct.Value[1], ksk.GadgetParams)
	e.ScalarMulLWETo(e.buf.ctProdLWE, ksk.Value[0].Value[0], cDcmp[0])
	for j := 1; j < ksk.GadgetParams.level; j++ {
		e.ScalarMulAddLWETo(e.buf.ctProdLWE, ksk.Value[0].Value[j], cDcmp[j])
	}

	for i := 1; i < ksk.InputLWEDimension(); i++ {
		e.Decomposer.DecomposeScalarTo(cDcmp, ct.Value[i+1], ksk.GadgetParams)
		for j := 0; j < ksk.GadgetParams.level; j++ {
			e.ScalarMulAddLWETo(e.buf.ctProdLWE, ksk.Value[i].Value[j], cDcmp[j])
		}
	}

	ctOut.Value[0] = ct.Value[0] + e.buf.ctProdLWE.Value[0]
	copy(ctOut.Value[1:], e.buf.ctProdLWE.Value[1:])
}

// KeySwitchGLWE switches key of ct.
// Input ciphertext should be of length ksk.InputGLWERank + 1.
func (e *Evaluator[T]) KeySwitchGLWE(ct GLWECiphertext[T], ksk GLWEKeySwitchKey[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.KeySwitchGLWETo(ctOut, ct, ksk)
	return ctOut
}

// KeySwitchGLWETo switches key of ct and writes it to ctOut.
// Input ciphertext should be of length ksk.InputGLWERank + 1.
func (e *Evaluator[T]) KeySwitchGLWETo(ctOut, ct GLWECiphertext[T], ksk GLWEKeySwitchKey[T]) {
	fpDcmp := e.Decomposer.FFTPolyBuffer(ksk.GadgetParameters)

	e.Decomposer.FourierDecomposePolyTo(fpDcmp, ct.Value[1], ksk.GadgetParameters)
	e.FFTPolyMulFFTGLWETo(e.buf.ctFFTProdGLWE, ksk.Value[0].Value[0], fpDcmp[0])
	for j := 1; j < ksk.GadgetParameters.level; j++ {
		e.FFTPolyMulAddFFTGLWETo(e.buf.ctFFTProdGLWE, ksk.Value[0].Value[j], fpDcmp[j])
	}

	for i := 1; i < ksk.InputGLWERank(); i++ {
		e.Decomposer.FourierDecomposePolyTo(fpDcmp, ct.Value[i+1], ksk.GadgetParameters)
		for j := 0; j < ksk.GadgetParameters.level; j++ {
			e.FFTPolyMulAddFFTGLWETo(e.buf.ctFFTProdGLWE, ksk.Value[i].Value[j], fpDcmp[j])
		}
	}

	ctOut.Value[0].CopyFrom(ct.Value[0])
	e.PolyEvaluator.InvFFTAddToUnsafe(ctOut.Value[0], e.buf.ctFFTProdGLWE.Value[0])
	for i := 0; i < e.Params.glweRank; i++ {
		e.PolyEvaluator.InvFFTToUnsafe(ctOut.Value[i+1], e.buf.ctFFTProdGLWE.Value[i+1])
	}
}
