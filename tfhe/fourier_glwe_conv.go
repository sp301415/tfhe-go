package tfhe

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *Evaluator[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.ToFourierGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextAssign transforms GLWE ciphertext to Fourier GLWE ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToFourierGLWECiphertextAssign(ctIn GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledFourierPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *Evaluator[T]) ToStandardGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ToStandardGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGLWECiphertextAssign transforms Fourier GLWE ciphertext to GLWE ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToStandardGLWECiphertextAssign(ctIn FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e *Evaluator[T]) ToFourierGLevCiphertext(ct GLevCiphertext[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToFourierGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLevCiphertextAssign transforms GLev ciphertext to Fourier GLev ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToFourierGLevCiphertextAssign(ctIn GLevCiphertext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToFourierGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e *Evaluator[T]) ToStandardGLevCiphertext(ct FourierGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToStandardGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGLevCiphertextAssign transforms Fourier GLev ciphertext to GLev ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToStandardGLevCiphertextAssign(ctIn FourierGLevCiphertext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToStandardGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e *Evaluator[T]) ToFourierGGSWCiphertext(ct GGSWCiphertext[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToFourierGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGGSWCiphertextAssign transforms GGSW ciphertext to Fourier GGSW ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToFourierGGSWCiphertextAssign(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToFourierGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e *Evaluator[T]) ToStandardGGSWCiphertext(ct FourierGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToStandardGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGGSWCiphertextAssign transforms Fourier GGSW ciphertext to GGSW ciphertext, and writes it to ctOut.
func (e *Evaluator[T]) ToStandardGGSWCiphertextAssign(ctIn FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToStandardGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

/* Same methods, but for encryptor */

// ToFourierGLWECiphertext transforms GLWE ciphertext to Fourier GLWE ciphertext.
func (e *Encryptor[T]) ToFourierGLWECiphertext(ct GLWECiphertext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.ToFourierGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLWECiphertextAssign transforms GLWE ciphertext to Fourier GLWE ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToFourierGLWECiphertextAssign(ctIn GLWECiphertext[T], ctOut FourierGLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledFourierPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLWECiphertext transforms Fourier GLWE ciphertext to GLWE ciphertext.
func (e *Encryptor[T]) ToStandardGLWECiphertext(ct FourierGLWECiphertext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.ToStandardGLWECiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGLWECiphertextAssign transforms Fourier GLWE ciphertext to GLWE ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToStandardGLWECiphertextAssign(ctIn FourierGLWECiphertext[T], ctOut GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierEvaluator.ToScaledStandardPolyAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGLevCiphertext transforms GLev ciphertext to Fourier GLev ciphertext.
func (e *Encryptor[T]) ToFourierGLevCiphertext(ct GLevCiphertext[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToFourierGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGLevCiphertextAssign transforms GLev ciphertext to Fourier GLev ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToFourierGLevCiphertextAssign(ctIn GLevCiphertext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToFourierGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGLevCiphertext transforms Fourier GLev ciphertext to GLev ciphertext.
func (e *Encryptor[T]) ToStandardGLevCiphertext(ct FourierGLevCiphertext[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToStandardGLevCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGLevCiphertextAssign transforms Fourier GLev ciphertext to GLev ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToStandardGLevCiphertextAssign(ctIn FourierGLevCiphertext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctIn.GadgetParameters.level; i++ {
		e.ToStandardGLWECiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToFourierGGSWCiphertext transforms GGSW ciphertext to Fourier GGSW ciphertext.
func (e *Encryptor[T]) ToFourierGGSWCiphertext(ct GGSWCiphertext[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToFourierGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToFourierGGSWCiphertextAssign transforms GGSW ciphertext to Fourier GGSW ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToFourierGGSWCiphertextAssign(ctIn GGSWCiphertext[T], ctOut FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToFourierGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}

// ToStandardGGSWCiphertext transforms Fourier GGSW ciphertext to GGSW ciphertext.
func (e *Encryptor[T]) ToStandardGGSWCiphertext(ct FourierGGSWCiphertext[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, ct.GadgetParameters)
	e.ToStandardGGSWCiphertextAssign(ct, ctOut)
	return ctOut
}

// ToStandardGGSWCiphertextAssign transforms Fourier GGSW ciphertext to GGSW ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) ToStandardGGSWCiphertextAssign(ctIn FourierGGSWCiphertext[T], ctOut GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.ToStandardGLevCiphertextAssign(ctIn.Value[i], ctOut.Value[i])
	}
}
