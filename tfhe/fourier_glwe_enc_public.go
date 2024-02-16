package tfhe

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLWEPlaintext(pt GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ct := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLWEPlaintextAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}

// EncryptFourierGLev encrypts integer message to FourierGLev ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLev(messages []int, gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGLevPlaintext(pt, gadgetParams)
}

// EncryptFourierGLevPlaintext encrypts GLWE plaintext to FourierGLev ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLevPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := NewFourierGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLevPlaintextAssign encrypts GLWE plaintext to FourierGLev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLevPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.GLWEPolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.ScaledBase(i), e.buffer.ctGLWE.Value[0])
		e.EncryptGLWEBody(e.buffer.ctGLWE)
		e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i])
	}
}
