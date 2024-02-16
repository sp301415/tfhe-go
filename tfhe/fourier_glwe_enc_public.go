package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEAssign encrypts and encrypts integer messages to FourierGLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLWEAssign(messages []int, ctOut FourierGLWECiphertext[T]) {
	e.EncryptFourierGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
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
	ctOut := NewFourierGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGLevAssign(messages, ctOut)
	return ctOut
}

// EncryptFourierGLevAssign encrypts integer message to FourierGLev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptFourierGLevAssign(messages []int, ctOut FourierGLevCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptFourierGLevPlaintextAssign(e.buffer.ptGLWE, ctOut)
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
