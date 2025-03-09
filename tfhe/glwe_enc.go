package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEAssign(messages, ctOut)
	return ctOut
}

// EncryptGLWEAssign encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEAssign(messages []int, ctOut GLWECiphertext[T]) {
	e.EncodeGLWEAssign(messages, e.buffer.ptGLWE)
	e.EncryptGLWEPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.UniformSampler.SamplePolyAssign(ct.Value[i+1])
		e.PolyEvaluator.ShortFourierPolyMulSubPolyAssign(ct.Value[i+1], e.SecretKey.FourierGLWEKey.Value[i], ct.Value[0])
	}

	e.GaussianSampler.SamplePolyAddAssign(e.Parameters.GLWEStdDevQ(), ct.Value[0])
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	e.DecryptGLWEPhaseAssign(ct, e.buffer.ptGLWE)
	return e.DecodeGLWE(e.buffer.ptGLWE)
}

// DecryptGLWEAssign decrypts and decodes GLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGLWEAssign(ct GLWECiphertext[T], messagesOut []int) {
	e.DecryptGLWEPhaseAssign(ct, e.buffer.ptGLWE)
	e.DecodeGLWEAssign(e.buffer.ptGLWE, messagesOut)
}

// DecryptGLWEPhase decrypts GLWE ciphertext to GLWE plaintext including errors.
func (e *Encryptor[T]) DecryptGLWEPhase(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEPhaseAssign(ct, ptOut)
	return ptOut
}

// DecryptGLWEPhaseAssign decrypts GLWE ciphertext to GLWE plaintext including errors and writes it to ptOut.
func (e *Encryptor[T]) DecryptGLWEPhaseAssign(ct GLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	ptOut.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(ct.Value[i+1], e.SecretKey.FourierGLWEKey.Value[i], ptOut.Value)
	}
}

// EncryptGLev encrypts integer message to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLev(messages []int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevAssign(messages, ct)
	return ct
}

// EncryptGLevAssign encrypts integer message to GLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevAssign(messages []int, ctOut GLevCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGLevPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// EncryptGLevPoly encrypts polynomial to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLevPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevPolyAssign(p, ctOut)
	return ctOut
}

// EncryptGLevPolyAssign encrypts polynomial to GLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevPolyAssign(p poly.Poly[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.PolyEvaluator.ScalarMulPolyAssign(p, ctOut.GadgetParameters.BaseQ(i), ctOut.Value[i].Value[0])
		e.EncryptGLWEBody(ctOut.Value[i])
	}
}

// DecryptGLev decrypts GLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLev(ct GLevCiphertext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	e.DecryptGLevAssign(ct, messages)
	return messages
}

// DecryptGLevAssign decrypts GLev ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGLevAssign(ct GLevCiphertext[T], messagesOut []int) {
	e.DecryptGLevPolyAssign(ct, e.buffer.ptGLWE.Value)

	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buffer.ptGLWE.Value.Coeffs[i] % e.Parameters.messageModulus)
	}
}

// DecryptGLevPoly decrypts GLev ciphertext to polynomial.
func (e *Encryptor[T]) DecryptGLevPoly(ct GLevCiphertext[T]) poly.Poly[T] {
	p := poly.NewPoly[T](e.Parameters.polyDegree)
	e.DecryptGLevPolyAssign(ct, p)
	return p
}

// DecryptGLevPolyAssign decrypts GLev ciphertext to poly and writes it to pOut.
func (e *Encryptor[T]) DecryptGLevPolyAssign(ct GLevCiphertext[T], pOut poly.Poly[T]) {
	e.DecryptGLWEPhaseAssign(ct.Value[0], GLWEPlaintext[T]{Value: pOut})
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParameters.LogFirstBaseQ()) % ct.GadgetParameters.base
	}
}

// EncryptGGSW encrypts integer message to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSW(messages []int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	return e.EncryptGGSWPoly(e.buffer.ptGLWE.Value, gadgetParams)
}

// EncryptGGSWAssign encrypts integer message to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWAssign(messages []int, ctOut GGSWCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGGSWPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// EncryptGGSWPoly encrypts polynomial to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSWPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptGGSWPolyAssign(p, ctOut)
	return ctOut
}

// EncryptGGSWPolyAssign encrypts polynomial to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWPolyAssign(p poly.Poly[T], ctOut GGSWCiphertext[T]) {
	e.EncryptGLevPolyAssign(p, ctOut.Value[0])
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.PolyEvaluator.ShortFourierPolyMulPolyAssign(p, e.SecretKey.FourierGLWEKey.Value[i], e.buffer.ptGGSW)
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			e.PolyEvaluator.ScalarMulPolyAssign(e.buffer.ptGGSW, ctOut.GadgetParameters.BaseQ(j), ctOut.Value[i+1].Value[j].Value[0])
			e.EncryptGLWEBody(ctOut.Value[i+1].Value[j])
		}
	}
}

// DecryptGGSW decrypts GGSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptGGSW(ct GGSWCiphertext[T]) []int {
	return e.DecryptGLev(ct.Value[0])
}

// DecryptGGSWAssign decrypts GGSW ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGGSWAssign(ct GGSWCiphertext[T], messagesOut []int) {
	e.DecryptGLevAssign(ct.Value[0], messagesOut)
}

// DecryptGGSWPoly decrypts GGSW ciphertext to polynomial.
func (e *Encryptor[T]) DecryptGGSWPoly(ct GGSWCiphertext[T]) poly.Poly[T] {
	return e.DecryptGLevPoly(ct.Value[0])
}

// DecryptGGSWPolyAssign decrypts GGSW ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptGGSWPolyAssign(ct GGSWCiphertext[T], pOut poly.Poly[T]) {
	e.DecryptGLevPolyAssign(ct.Value[0], pOut)
}
