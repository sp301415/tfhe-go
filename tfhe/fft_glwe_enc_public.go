package tfhe

// EncryptFFTGLWE encodes and encrypts integer messages to FFTGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFFTGLWE(messages []int) FFTGLWECiphertext[T] {
	return e.EncryptFFTGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFFTGLWETo encrypts and encrypts integer messages to FFTGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFFTGLWETo(ctOut FFTGLWECiphertext[T], messages []int) {
	e.EncryptFFTGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptFFTGLWEPlaintext encrypts GLWE plaintext to FFTGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFFTGLWEPlaintext(pt GLWEPlaintext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.EncryptFFTGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptFFTGLWEPlaintextTo encrypts GLWE plaintext to FFTGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFFTGLWEPlaintextTo(ctOut FFTGLWECiphertext[T], pt GLWEPlaintext[T]) {
	e.EncryptGLWEPlaintextTo(e.buf.ctGLWE, pt)
	e.FFTGLWECiphertextTo(ctOut, e.buf.ctGLWE)
}
