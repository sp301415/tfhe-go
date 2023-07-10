package tfhe

import "github.com/sp301415/tfhe/math/num"

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e Encrypter[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEPlaintext encrypts GLWE plaintext to FourierGLWE ciphertext.
func (e Encrypter[T]) EncryptFourierGLWEPlaintext(pt GLWEPlaintext[T]) FourierGLWECiphertext[T] {
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEInPlace(pt, ctOut)
	return ctOut
}

// EncryptFourierGLWEInPlace encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e Encrypter[T]) EncryptFourierGLWEInPlace(pt GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEInPlace(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextInPlace(e.buffer.ctGLWE, ctOut)
}

// DecryptFourierGLWE decrypts and decodes FourierGLWE ciphertext to integer message.
func (e Encrypter[T]) DecryptFourierGLWE(ct FourierGLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptFourierGLWEPlaintext(ct))
}

// DecryptFourierGLWEPlaintext decrypts FourierGLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGLWEPlaintext(ct FourierGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLWEInPlace(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEInPlace decrypts FourierGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encrypter[T]) DecryptFourierGLWEInPlace(ct FourierGLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	e.ToStandardGLWECiphertextInPlace(ct, e.buffer.ctGLWE)
	e.DecryptGLWEInPlace(e.buffer.ctGLWE, ptOut)
}

// EncryptFourierGLev encrypts integer message to FourierGLev ciphertext.
func (e Encrypter[T]) EncryptFourierGLev(messages []int, decompParams DecompositionParameters[T]) FourierGLevCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGLevPlaintext(pt, decompParams)
}

// EncryptFourierGLevPlaintext encrypts GLWE plaintext to FourierGLev ciphertext.
func (e Encrypter[T]) EncryptFourierGLevPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, decompParams)
	e.EncryptFourierGLevInPlace(pt, ctOut)
	return ctOut
}

// EncryptFourierGLevInPlace encrypts GLWE plaintext to FourierGLev ciphertext, and writes it to ctOut.
func (e Encrypter[T]) EncryptFourierGLevInPlace(pt GLWEPlaintext[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctOut.decompParams.level; i++ {
		e.PolyEvaluater.ScalarMulInPlace(pt.Value, ctOut.decompParams.ScaledBase(i), e.buffer.ctGLWE.Value[0])
		e.EncryptGLWEBody(e.buffer.ctGLWE)
		e.ToFourierGLWECiphertextInPlace(e.buffer.ctGLWE, ctOut.Value[i])
	}
}

// DecryptFourierGLev decrypts FourierGLev ciphertext to integer message.
func (e Encrypter[T]) DecryptFourierGLev(ct FourierGLevCiphertext[T]) []int {
	pt := e.DecryptFourierGLevPlaintext(ct)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
	return messages
}

// DecryptFourierGLevPlaintext decrypts FourierGLev ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGLevPlaintext(ct FourierGLevCiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLevInPlace(ct, ptOut)
	return ptOut
}

// DecryptFourierGLevInPlace decrypts FourierGLev ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encrypter[T]) DecryptFourierGLevInPlace(ct FourierGLevCiphertext[T], ptOut GLWEPlaintext[T]) {
	ctLastLevel := ct.Value[ct.decompParams.level-1]
	e.DecryptFourierGLWEInPlace(ctLastLevel, ptOut)
}

// EncryptFourierGGSW encrypts integer message to FourierGGSW ciphertext.
func (e Encrypter[T]) EncryptFourierGGSW(messages []int, decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGGSWPlaintext(pt, decompParams)
}

// EncryptFourierGGSWPlaintext encrypts GLWE plaintext to FourierGGSW ciphertext.
func (e Encrypter[T]) EncryptFourierGGSWPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptFourierGGSWInPlace(pt, ctOut)
	return ctOut
}

// EncryptFourierGGSWInPlace encrypts GLWE plaintext to FourierGGSW ciphertext, and writes it to ctOut.
func (e Encrypter[T]) EncryptFourierGGSWInPlace(pt GLWEPlaintext[T], ctOut FourierGGSWCiphertext[T]) {
	e.EncryptFourierGLevInPlace(pt, ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluater.MulInPlace(e.SecretKey.GLWEKey.Value[i-1], pt.Value, e.buffer.ptForGGSW)
		for j := 0; j < ctOut.decompParams.level; j++ {
			e.PolyEvaluater.ScalarMulInPlace(e.buffer.ptForGGSW, -ctOut.decompParams.ScaledBase(j), e.buffer.ctGLWE.Value[0])
			e.EncryptGLWEBody(e.buffer.ctGLWE)
			e.ToFourierGLWECiphertextInPlace(e.buffer.ctGLWE, ctOut.Value[i].Value[j])
		}
	}
}

// DecryptFourierGGSW decrypts FourierGGSW ciphertext to integer message.
func (e Encrypter[T]) DecryptFourierGGSW(ct FourierGGSWCiphertext[T]) []int {
	return e.DecryptFourierGLev(ct.Value[0])
}

// DecryptFourierGGSWPlaintext decrypts FourierGGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGGSWPlaintext(ct FourierGGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptFourierGLevPlaintext(ct.Value[0])
}

// DecryptFourierGGSWInPlace decrypts FourierGGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encrypter[T]) DecryptFourierGGSWInPlace(ct FourierGGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptFourierGLevInPlace(ct.Value[0], ptOut)
}
