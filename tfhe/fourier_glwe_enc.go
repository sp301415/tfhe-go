package tfhe

import "github.com/sp301415/tfhe-go/math/num"

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *Encryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e *Encryptor[T]) EncryptFourierGLWEPlaintext(pt GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ct := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLWEPlaintextAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}

// DecryptFourierGLWE decrypts and decodes FourierGLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGLWE(ct FourierGLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptFourierGLWEPlaintext(ct))
}

// DecryptFourierGLWEPlaintext decrypts FourierGLWE ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptFourierGLWEPlaintext(ct FourierGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLWEPlaintextAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEPlaintextAssign decrypts FourierGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGLWEPlaintextAssign(ct FourierGLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	e.ToStandardGLWECiphertextAssign(ct, e.buffer.ctGLWE)
	e.DecryptGLWEPlaintextAssign(e.buffer.ctGLWE, ptOut)
}

// EncryptFourierGLev encrypts integer message to FourierGLev ciphertext.
func (e *Encryptor[T]) EncryptFourierGLev(messages []int, gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGLevPlaintext(pt, gadgetParams)
}

// EncryptFourierGLevPlaintext encrypts GLWE plaintext to FourierGLev ciphertext.
func (e *Encryptor[T]) EncryptFourierGLevPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ct := NewFourierGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGLevPlaintextAssign encrypts GLWE plaintext to FourierGLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLevPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.PolyEvaluator.ScalarMulAssign(ctOut.GadgetParameters.ScaledBase(i), pt.Value, e.buffer.ctGLWE.Value[0])
		e.EncryptGLWEBody(e.buffer.ctGLWE)
		e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i])
	}
}

// DecryptFourierGLev decrypts FourierGLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGLev(ct FourierGLevCiphertext[T]) []int {
	pt := e.DecryptFourierGLevPlaintext(ct)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], ct.GadgetParameters.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
	return messages
}

// DecryptFourierGLevPlaintext decrypts FourierGLev ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptFourierGLevPlaintext(ct FourierGLevCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLevPlaintextAssign(ct, pt)
	return pt
}

// DecryptFourierGLevPlaintextAssign decrypts FourierGLev ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGLevPlaintextAssign(ct FourierGLevCiphertext[T], ptOut GLWEPlaintext[T]) {
	ctLastLevel := ct.Value[ct.GadgetParameters.level-1]
	e.DecryptFourierGLWEPlaintextAssign(ctLastLevel, ptOut)
}

// EncryptFourierGGSW encrypts integer message to FourierGGSW ciphertext.
func (e *Encryptor[T]) EncryptFourierGGSW(messages []int, gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGGSWPlaintext(pt, gadgetParams)
}

// EncryptFourierGGSWPlaintext encrypts GLWE plaintext to FourierGGSW ciphertext.
func (e *Encryptor[T]) EncryptFourierGGSWPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ct := NewFourierGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGGSWPlaintextAssign(pt, ct)
	return ct
}

// EncryptFourierGGSWPlaintextAssign encrypts GLWE plaintext to FourierGGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGGSWPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGGSWCiphertext[T]) {
	e.EncryptFourierGLevPlaintextAssign(pt, ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.mulFourierGLWEKeyAssign(pt.Value, e.SecretKey.FourierGLWEKey.Value[i-1], e.buffer.ptGGSW)
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			e.PolyEvaluator.ScalarMulAssign(ctOut.GadgetParameters.ScaledBase(j), e.buffer.ptGGSW, e.buffer.ctGLWE.Value[0])
			e.EncryptGLWEBody(e.buffer.ctGLWE)
			e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i].Value[j])
		}
	}
}

// DecryptFourierGGSW decrypts FourierGGSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGGSW(ct FourierGGSWCiphertext[T]) []int {
	return e.DecryptFourierGLev(ct.Value[0])
}

// DecryptFourierGGSWPlaintext decrypts FourierGGSW ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptFourierGGSWPlaintext(ct FourierGGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptFourierGLevPlaintext(ct.Value[0])
}

// DecryptFourierGGSWPlaintextAssign decrypts FourierGGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGGSWPlaintextAssign(ct FourierGGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptFourierGLevPlaintextAssign(ct.Value[0], ptOut)
}
