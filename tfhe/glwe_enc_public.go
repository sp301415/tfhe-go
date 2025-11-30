package tfhe

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWETo(ctOut, messages)
	return ctOut
}

// EncryptGLWETo encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWETo(ctOut GLWECiphertext[T], messages []int) {
	e.EncodeGLWETo(e.buf.ptGLWE, messages)
	e.EncryptGLWEPlaintextTo(ctOut, e.buf.ptGLWE)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptGLWEPlaintextTo encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintextTo(ctOut GLWECiphertext[T], pt GLWEPlaintext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank; i++ {
		e.BinarySampler.SamplePolyTo(e.buf.auxKey.Value[i])
	}
	e.FwdFFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	e.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ct.Value[0], e.PublicKey.GLWEKey.Value[0].Value[0], e.buf.auxFourierKey.Value[0])
	for j := 1; j < e.Params.glweRank+1; j++ {
		e.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ct.Value[j], e.PublicKey.GLWEKey.Value[0].Value[j], e.buf.auxFourierKey.Value[0])
	}
	for i := 1; i < e.Params.glweRank; i++ {
		for j := 0; j < e.Params.glweRank+1; j++ {
			e.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ct.Value[j], e.PublicKey.GLWEKey.Value[i].Value[j], e.buf.auxFourierKey.Value[i])
		}
	}

	for j := 0; j < e.Params.glweRank+1; j++ {
		e.GaussianSampler.SamplePolyAddTo(ct.Value[j], e.Params.GLWEStdDevQ())
	}
}
