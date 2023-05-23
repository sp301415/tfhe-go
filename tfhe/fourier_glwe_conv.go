package tfhe

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e Encrypter[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.ToFourierGLWECiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextInPlace transforms GLWE ciphertext to Fourier GLWE ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToFourierGLWECiphertextInPlace(ctIn GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledFourierPolyInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e Encrypter[T]) ToStandardGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ToStandardGLWECiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToStandardGLWECiphertextInPlace transforms Fourier GLWE ciphertext to GLWE ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToStandardGLWECiphertextInPlace(ctIn FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e Encrypter[T]) ToFourierGLevCiphertext(ct GLevCiphertext[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, ct.decompParams)
	e.ToFourierGLevCiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToFourierGLevCiphertextInPlace transforms GLev ciphertext to Fourier GLev ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToFourierGLevCiphertextInPlace(ctIn GLevCiphertext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctIn.decompParams.level; i++ {
		e.ToFourierGLWECiphertextInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e Encrypter[T]) ToStandardGLevCiphertext(ct FourierGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, ct.decompParams)
	e.ToStandardGLevCiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToStandardGLevCiphertextInPlace transforms Fourier GLev ciphertext to GLev ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToStandardGLevCiphertextInPlace(ctIn FourierGLevCiphertext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctIn.decompParams.level; i++ {
		e.ToStandardGLWECiphertextInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e Encrypter[T]) ToFourierGGSWCiphertext(ct GGSWCiphertext[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, ct.decompParams)
	e.ToFourierGGSWCiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToFourierGGSWCiphertextInPlace transforms GGSW ciphertext to Fourier GGSW ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToFourierGGSWCiphertextInPlace(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToFourierGLevCiphertextInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e Encrypter[T]) ToStandardGGSWCiphertext(ct FourierGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, ct.decompParams)
	e.ToStandardGGSWCiphertextInPlace(ct, ctOut)
	return ctOut
}

// ToStandardGGSWCiphertextInPlace transforms Fourier GGSW ciphertext to GGSW ciphertext, and writes it to ctOut.
func (e Encrypter[T]) ToStandardGGSWCiphertextInPlace(ctIn FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToStandardGLevCiphertextInPlace(ctIn.Value[i], ctOut.Value[i])
	}
}
