package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
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
	ctOut := NewFourierGLWECiphertext(e.Parameters)
	e.EncryptFourierGLWEPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptFourierGLWEPlaintextAssign encrypts GLWE plaintext to FourierGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut FourierGLWECiphertext[T]) {
	e.EncryptGLWEPlaintextAssign(pt, e.buffer.ctGLWE)
	e.ToFourierGLWECiphertextAssign(e.buffer.ctGLWE, ctOut)
}

// DecryptFourierGLWE decrypts and decodes FourierGLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptFourierGLWE(ct FourierGLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptFourierGLWEPhase(ct))
}

// DecryptFourierGLWEAssign decrypts and decodes FourierGLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFourierGLWEAssign(ct FourierGLWECiphertext[T], messagesOut []int) {
	e.DecodeGLWEAssign(e.DecryptFourierGLWEPhase(ct), messagesOut)
}

// DecryptFourierGLWEPhase decrypts FourierGLWE ciphertext to GLWE plaintext including errors.
func (e *Encryptor[T]) DecryptFourierGLWEPhase(ct FourierGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGLWEPolyAssign(ct, ptOut)
	return ptOut
}

// DecryptFourierGLWEPolyAssign decrypts FourierGLWE ciphertext to GLWE plaintext including errors and writes it to ptOut.
func (e *Encryptor[T]) DecryptFourierGLWEPolyAssign(ct FourierGLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	e.ToGLWECiphertextAssign(ct, e.buffer.ctGLWE)
	e.DecryptGLWEPhaseAssign(e.buffer.ctGLWE, ptOut)
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

	e.EncryptFourierGLevPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// EncryptFourierGLevPoly encrypts polynomial to FourierGLev ciphertext.
func (e *Encryptor[T]) EncryptFourierGLevPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) FourierGLevCiphertext[T] {
	ctOut := NewFourierGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGLevPolyAssign(p, ctOut)
	return ctOut
}

// EncryptFourierGLevPolyAssign encrypts polynomial to FourierGLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGLevPolyAssign(p poly.Poly[T], ctOut FourierGLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.PolyEvaluator.ScalarMulPolyAssign(p, ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWE.Value[0])
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
	e.DecryptFourierGLevPolyAssign(ct, e.buffer.ptGLWE.Value)

	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buffer.ptGLWE.Value.Coeffs[i] % e.Parameters.messageModulus)
	}
}

// DecryptFourierGLevPoly decrypts FourierGLev ciphertext to polynomial.
func (e *Encryptor[T]) DecryptFourierGLevPoly(ct FourierGLevCiphertext[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Parameters.polyDegree)
	e.DecryptFourierGLevPolyAssign(ct, pOut)
	return pOut
}

// DecryptFourierGLevPolyAssign decrypts FourierGLev ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptFourierGLevPolyAssign(ct FourierGLevCiphertext[T], pOut poly.Poly[T]) {
	e.DecryptFourierGLWEPolyAssign(ct.Value[0], GLWEPlaintext[T]{Value: pOut})
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParameters.LogFirstBaseQ()) % ct.GadgetParameters.base
	}
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

	e.EncryptFourierGGSWPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// EncryptFourierGGSWPoly encrypts polynomial to FourierGGSW ciphertext.
func (e *Encryptor[T]) EncryptFourierGGSWPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) FourierGGSWCiphertext[T] {
	ctOut := NewFourierGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptFourierGGSWPolyAssign(p, ctOut)
	return ctOut
}

// EncryptFourierGGSWPolyAssign encrypts polynomial to FourierGGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFourierGGSWPolyAssign(p poly.Poly[T], ctOut FourierGGSWCiphertext[T]) {
	e.EncryptFourierGLevPolyAssign(p, ctOut.Value[0])
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.PolyEvaluator.ShortFourierPolyMulPolyAssign(p, e.SecretKey.FourierGLWEKey.Value[i], e.buffer.ptGGSW)
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

// DecryptFourierGGSWPoly decrypts FourierGGSW ciphertext to polynomial.
func (e *Encryptor[T]) DecryptFourierGGSWPoly(ct FourierGGSWCiphertext[T]) poly.Poly[T] {
	return e.DecryptFourierGLevPoly(ct.Value[0])
}

// DecryptFourierGGSWPolyAssign decrypts FourierGGSW ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptFourierGGSWPolyAssign(ct FourierGGSWCiphertext[T], pOut poly.Poly[T]) {
	e.DecryptFourierGLevPolyAssign(ct.Value[0], pOut)
}
