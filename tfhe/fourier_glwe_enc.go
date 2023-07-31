package tfhe

import "github.com/sp301415/tfhe/math/num"

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e Encryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e Encryptor[T]) EncryptFourierGLWEPlaintext(pt GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEAssign(pt, ctOut)
	return ctOut
}

// EncryptFourierGLWEAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e Encryptor[T]) EncryptFourierGLWEAssign(pt GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}

// DecryptFourierGLWE decrypts and decodes FourierGLWE ciphertext to integer message.
func (e Encryptor[T]) DecryptFourierGLWE(ct FourierGLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptFourierGLWEPlaintext(ct))
}

// DecryptFourierGLWEPlaintext decrypts FourierGLWE ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptFourierGLWEPlaintext(ct FourierGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLWEAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEAssign decrypts FourierGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptFourierGLWEAssign(ct FourierGLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	e.ToStandardGLWECiphertextAssign(ct, e.buffer.ctGLWE)
	e.DecryptGLWEAssign(e.buffer.ctGLWE, ptOut)
}

// EncryptFourierGLev encrypts integer message to FourierGLev ciphertext.
func (e Encryptor[T]) EncryptFourierGLev(messages []int, decompParams DecompositionParameters[T]) FourierGLevCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGLevPlaintext(pt, decompParams)
}

// EncryptFourierGLevPlaintext encrypts GLWE plaintext to FourierGLev ciphertext.
func (e Encryptor[T]) EncryptFourierGLevPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, decompParams)
	e.EncryptFourierGLevAssign(pt, ctOut)
	return ctOut
}

// EncryptFourierGLevAssign encrypts GLWE plaintext to FourierGLev ciphertext, and writes it to ctOut.
func (e Encryptor[T]) EncryptFourierGLevAssign(pt GLWEPlaintext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctOut.decompParams.level; i++ {
		e.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.decompParams.ScaledBase(i), e.buffer.ctGLWE.Value[0])
		e.EncryptGLWEBody(e.buffer.ctGLWE)
		e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i])
	}
}

// DecryptFourierGLev decrypts FourierGLev ciphertext to integer message.
func (e Encryptor[T]) DecryptFourierGLev(ct FourierGLevCiphertext[T]) []int {
	pt := e.DecryptFourierGLevPlaintext(ct)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
	return messages
}

// DecryptFourierGLevPlaintext decrypts FourierGLev ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptFourierGLevPlaintext(ct FourierGLevCiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLevAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLevAssign decrypts FourierGLev ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptFourierGLevAssign(ct FourierGLevCiphertext[T], ptOut GLWEPlaintext[T]) {
	ctLastLevel := ct.Value[ct.decompParams.level-1]
	e.DecryptFourierGLWEAssign(ctLastLevel, ptOut)
}

// EncryptFourierGGSW encrypts integer message to FourierGGSW ciphertext.
func (e Encryptor[T]) EncryptFourierGGSW(messages []int, decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGGSWPlaintext(pt, decompParams)
}

// EncryptFourierGGSWPlaintext encrypts GLWE plaintext to FourierGGSW ciphertext.
func (e Encryptor[T]) EncryptFourierGGSWPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptFourierGGSWAssign(pt, ctOut)
	return ctOut
}

// EncryptFourierGGSWAssign encrypts GLWE plaintext to FourierGGSW ciphertext, and writes it to ctOut.
func (e Encryptor[T]) EncryptFourierGGSWAssign(pt GLWEPlaintext[T], ctOut FourierGGSWCiphertext[T]) {
	e.EncryptFourierGLevAssign(pt, ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulAssign(e.SecretKey.GLWEKey.Value[i-1], pt.Value, e.buffer.ptGGSW)
		for j := 0; j < ctOut.decompParams.level; j++ {
			e.PolyEvaluator.ScalarMulAssign(e.buffer.ptGGSW, -ctOut.decompParams.ScaledBase(j), e.buffer.ctGLWE.Value[0])
			e.EncryptGLWEBody(e.buffer.ctGLWE)
			e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i].Value[j])
		}
	}
}

// DecryptFourierGGSW decrypts FourierGGSW ciphertext to integer message.
func (e Encryptor[T]) DecryptFourierGGSW(ct FourierGGSWCiphertext[T]) []int {
	return e.DecryptFourierGLev(ct.Value[0])
}

// DecryptFourierGGSWPlaintext decrypts FourierGGSW ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptFourierGGSWPlaintext(ct FourierGGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptFourierGLevPlaintext(ct.Value[0])
}

// DecryptFourierGGSWAssign decrypts FourierGGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptFourierGGSWAssign(ct FourierGGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptFourierGLevAssign(ct.Value[0], ptOut)
}
