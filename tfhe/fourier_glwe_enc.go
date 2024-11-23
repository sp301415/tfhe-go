package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptFourierGLWE encodes and encrypts integer messages to FourierGLWE ciphertext.
func (e *Encryptor[T]) EncryptFourierGLWE(messages []int) FourierGLWECiphertext[T] {
	return e.EncryptFourierGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFourierGLWEAssign encrypts and encrypts integer messages to FourierGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLWEAssign(messages []int, ctOut FourierGLWECiphertext[T]) {
	e.EncryptFourierGLWEPlaintextAssign(e.EncodeGLWE(messages), ctOut)
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

// DecryptFourierGLWEAssign decrypts and decodes FourierGLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFourierGLWEAssign(ct FourierGLWECiphertext[T], messagesOut []int) {
	e.DecodeGLWEAssign(e.DecryptFourierGLWEPlaintext(ct), messagesOut)
}

// DecryptFourierGLWEPlaintext decrypts FourierGLWE ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptFourierGLWEPlaintext(ct FourierGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLWEPlaintextAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEPlaintextAssign decrypts FourierGLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGLWEPlaintextAssign(ct FourierGLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	e.ToGLWECiphertextAssign(ct, e.buffer.ctGLWE)
	e.DecryptGLWEPlaintextAssign(e.buffer.ctGLWE, ptOut)
}

// EncryptFourierGLev encrypts integer message to FourierGLev ciphertext.
func (e *Encryptor[T]) EncryptFourierGLev(messages []int, gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGLevAssign(messages, ctOut)
	return ctOut
}

// EncryptFourierGLevAssign encrypts integer message to FourierGLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLevAssign(messages []int, ctOut FourierGLevCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptFourierGLevPlaintextAssign(e.buffer.ptGLWE, ctOut)
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
		e.PolyEvaluator.ScalarMulPolyAssign(pt.Value, ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWE.Value[0])
		e.EncryptGLWEBody(e.buffer.ctGLWE)
		e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i])
	}
}

// DecryptFourierGLev decrypts FourierGLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGLev(ct FourierGLevCiphertext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	e.DecryptFourierGLevAssign(ct, messages)
	return messages
}

// DecryptFourierGLevAssign decrypts FourierGLev ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFourierGLevAssign(ct FourierGLevCiphertext[T], messagesOut []int) {
	e.DecryptFourierGLevPlaintextAssign(ct, e.buffer.ptGLWE)

	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(num.DivRoundBits(e.buffer.ptGLWE.Value.Coeffs[i], ct.GadgetParameters.LogLastBaseQ()) % e.Parameters.messageModulus)
	}
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
	ctOut := NewFourierGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGGSWAssign(messages, ctOut)
	return ctOut
}

// EncryptFourierGGSWAssign encrypts integer message to FourierGGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGGSWAssign(messages []int, ctOut FourierGGSWCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptFourierGGSWPlaintextAssign(e.buffer.ptGLWE, ctOut)
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
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.PolyEvaluator.ShortFourierPolyMulPolyAssign(pt.Value, e.SecretKey.FourierGLWEKey.Value[i], e.buffer.ptGGSW)
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			e.PolyEvaluator.ScalarMulPolyAssign(e.buffer.ptGGSW, ctOut.GadgetParameters.BaseQ(j), e.buffer.ctGLWE.Value[0])
			e.EncryptGLWEBody(e.buffer.ctGLWE)
			e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut.Value[i+1].Value[j])
		}
	}
}

// DecryptFourierGGSW decrypts FourierGGSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGGSW(ct FourierGGSWCiphertext[T]) []int {
	return e.DecryptFourierGLev(ct.Value[0])
}

// DecryptFourierGGSWAssign decrypts FourierGGSW ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFourierGGSWAssign(ct FourierGGSWCiphertext[T], messagesOut []int) {
	e.DecryptFourierGLevAssign(ct.Value[0], messagesOut)
}

// DecryptFourierGGSWPlaintext decrypts FourierGGSW ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptFourierGGSWPlaintext(ct FourierGGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptFourierGLevPlaintext(ct.Value[0])
}

// DecryptFourierGGSWPlaintextAssign decrypts FourierGGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGGSWPlaintextAssign(ct FourierGGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptFourierGLevPlaintextAssign(ct.Value[0], ptOut)
}
