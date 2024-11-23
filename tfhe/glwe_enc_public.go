package tfhe

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEAssign(messages, ctOut)
	return ctOut
}

// EncryptGLWEAssign encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEAssign(messages []int, ctOut GLWECiphertext[T]) {
	e.EncodeGLWEAssign(messages, e.buffer.ptGLWE)
	e.EncryptGLWEPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.BinarySampler.SamplePolyAssign(e.buffer.auxKey.Value[i])
	}
	e.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	e.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(e.PublicKey.GLWEKey.Value[0].Value[0], e.buffer.auxFourierKey.Value[0], ct.Value[0])
	for j := 1; j < e.Parameters.glweRank+1; j++ {
		e.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(e.PublicKey.GLWEKey.Value[0].Value[j], e.buffer.auxFourierKey.Value[0], ct.Value[j])
	}
	for i := 1; i < e.Parameters.glweRank; i++ {
		for j := 0; j < e.Parameters.glweRank+1; j++ {
			e.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(e.PublicKey.GLWEKey.Value[i].Value[j], e.buffer.auxFourierKey.Value[i], ct.Value[j])
		}
	}

	for j := 0; j < e.Parameters.glweRank+1; j++ {
		e.GaussianSampler.SamplePolyAddAssign(e.Parameters.GLWEStdDevQ(), ct.Value[j])
	}
}
