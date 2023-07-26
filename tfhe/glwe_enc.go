package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
)

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	return e.EncryptGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e Encryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEInPlace(pt, ctOut)
	return ctOut
}

// EncryptGLWEInPlace encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e Encryptor[T]) EncryptGLWEInPlace(pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.uniformSampler.SampleSliceInPlace(ct.Value[i].Coeffs)
	}
	e.glweSampler.SampleSliceAddInPlace(ct.Value[0].Coeffs)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.PolyEvaluator.MulAddInPlace(ct.Value[i+1], e.SecretKey.GLWEKey.Value[i], ct.Value[0])
	}
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (e Encryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWEPlaintext(ct))
}

// DecryptGLWEPlaintext decrypts GLWE ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptGLWEPlaintext(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEInPlace(ct, ptOut)
	return ptOut
}

// DecryptGLWEInPlace decrypts GLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptGLWEInPlace(ct GLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	ptOut.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.PolyEvaluator.MulSubInPlace(ct.Value[i+1], e.SecretKey.GLWEKey.Value[i], ptOut.Value)
	}
}

// EncryptGLev encrypts integer message to GLev ciphertext.
func (e Encryptor[T]) EncryptGLev(messages []int, decompParams DecompositionParameters[T]) GLevCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptGLevPlaintext(pt, decompParams)
}

// EncryptGLevPlaintext encrypts GLWE plaintext to GLev ciphertext.
func (e Encryptor[T]) EncryptGLevPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, decompParams)
	e.EncryptGLevInPlace(pt, ctOut)
	return ctOut
}

// EncryptGLevInPlace encrypts GLWE plaintext to GLev ciphertext, and writes it to ctOut.
func (e Encryptor[T]) EncryptGLevInPlace(pt GLWEPlaintext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctOut.decompParams.level; i++ {
		e.PolyEvaluator.ScalarMulInPlace(pt.Value, ctOut.decompParams.ScaledBase(i), ctOut.Value[i].Value[0])
		e.EncryptGLWEBody(ctOut.Value[i])
	}
}

// DecryptGLev decrypts GLev ciphertext to integer message.
func (e Encryptor[T]) DecryptGLev(ct GLevCiphertext[T]) []int {
	pt := e.DecryptGLevPlaintext(ct)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
	return messages
}

// DecryptGLevPlaintext decrypts GLev ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptGLevPlaintext(ct GLevCiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevInPlace(ct, ptOut)
	return ptOut
}

// DecryptGLevInPlace decrypts GLev ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptGLevInPlace(ct GLevCiphertext[T], ptOut GLWEPlaintext[T]) {
	ctLastLevel := ct.Value[ct.decompParams.level-1]
	e.DecryptGLWEInPlace(ctLastLevel, ptOut)
}

// EncryptGGSW encrypts integer message to GGSW ciphertext.
func (e Encryptor[T]) EncryptGGSW(messages []int, decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptGGSWPlaintext(pt, decompParams)
}

// EncryptGGSWPlaintext encrypts GLWE plaintext to GGSW ciphertext.
func (e Encryptor[T]) EncryptGGSWPlaintext(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGGSWInPlace(pt, ctOut)
	return ctOut
}

// EncryptGGSWInPlace encrypts GLWE plaintext to GGSW ciphertext, and writes it to ctOut.
func (e Encryptor[T]) EncryptGGSWInPlace(pt GLWEPlaintext[T], ctOut GGSWCiphertext[T]) {
	e.EncryptGLevInPlace(pt, ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.PolyEvaluator.MulInPlace(e.SecretKey.GLWEKey.Value[i-1], pt.Value, e.buffer.ptForGGSW)
		for j := 0; j < ctOut.decompParams.level; j++ {
			e.PolyEvaluator.ScalarMulInPlace(e.buffer.ptForGGSW, -ctOut.decompParams.ScaledBase(j), ctOut.Value[i].Value[j].Value[0])
			e.EncryptGLWEBody(ctOut.Value[i].Value[j])
		}
	}
}

// DecryptGGSW decrypts GGSW ciphertext to integer message.
func (e Encryptor[T]) DecryptGGSW(ct GGSWCiphertext[T]) []int {
	return e.DecryptGLev(ct.Value[0])
}

// DecryptGGSWPlaintext decrypts GGSW ciphertext to GLWE plaintext.
func (e Encryptor[T]) DecryptGGSWPlaintext(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptGLevPlaintext(ct.Value[0])
}

// DecryptGGSWInPlace decrypts GGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e Encryptor[T]) DecryptGGSWInPlace(ct GGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptGLevInPlace(ct.Value[0], ptOut)
}
