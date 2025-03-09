package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// UniEncrypt encrypts integer messages to UniEncryption.
func (e *Encryptor[T]) UniEncrypt(messages []int, gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	ctOut := NewUniEncryption(e.Parameters, gadgetParams)
	e.UniEncryptAssign(messages, gadgetParams, ctOut)
	return ctOut
}

// UniEncryptAssign encrypts integer messages to UniEncryption and writes it to ctOut.
func (e *Encryptor[T]) UniEncryptAssign(messages []int, gadgetParams tfhe.GadgetParameters[T], ctOut UniEncryption[T]) {
	length := num.Min(e.Parameters.PolyDegree(), len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.MessageModulus()
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.UniEncryptPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// UniEncryptPoly encrypts polynomial to UniEncryption.
func (e *Encryptor[T]) UniEncryptPoly(p poly.Poly[T], gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	ctOut := NewUniEncryption(e.Parameters, gadgetParams)
	e.UniEncryptPolyAssign(p, ctOut)
	return ctOut
}

// UniEncryptPolyAssign encrypts polynomial to UniEncryption and writes it to ctOut.
func (e *Encryptor[T]) UniEncryptPolyAssign(p poly.Poly[T], ctOut UniEncryption[T]) {
	e.SingleKeyEncryptor.BinarySampler.SamplePolyAssign(e.buffer.auxKey.Value[0])
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		ctOut.Value[0].Value[i].Value[1].CopyFrom(e.CRS[i])
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulPolyAssign(p, ctOut.GadgetParameters.BaseQ(i), ctOut.Value[0].Value[i].Value[0])

		e.SingleKeyEncryptor.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(ctOut.Value[0].Value[i].Value[1], e.buffer.auxFourierKey.Value[0], ctOut.Value[0].Value[i].Value[0])
		e.SingleKeyEncryptor.GaussianSampler.SamplePolyAddAssign(e.Parameters.GLWEStdDevQ(), ctOut.Value[0].Value[i].Value[0])
	}

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulPolyAssign(e.buffer.auxKey.Value[0], ctOut.GadgetParameters.BaseQ(i), ctOut.Value[1].Value[i].Value[0])
		e.SingleKeyEncryptor.EncryptGLWEBody(ctOut.Value[1].Value[i])
	}
}

// UniDecrypt decrypts UniEncryption to integer messages.
func (e *Encryptor[T]) UniDecrypt(ct UniEncryption[T]) []int {
	messages := make([]int, e.Parameters.PolyDegree())
	e.UniDecryptAssign(ct, messages)
	return messages
}

// UniDecryptAssign decrypts UniEncryption to integer messages and writes it to messagesOut.
func (e *Encryptor[T]) UniDecryptAssign(ct UniEncryption[T], messagesOut []int) {
	e.UniDecryptPolyAssign(ct, e.buffer.ptGLWE.Value)

	length := num.Min(e.Parameters.PolyDegree(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buffer.ptGLWE.Value.Coeffs[i] % e.Parameters.MessageModulus())
	}
}

// UniDecryptPoly decrypts UniEncryption to polynomial.
func (e *Encryptor[T]) UniDecryptPoly(ct UniEncryption[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Parameters.PolyDegree())
	e.UniDecryptPolyAssign(ct, pOut)
	return pOut
}

// UniDecryptPolyAssign decrypts UniEncryption to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) UniDecryptPolyAssign(ct UniEncryption[T], pOut poly.Poly[T]) {
	e.SingleKeyEncryptor.DecryptGLevPolyAssign(ct.Value[1], e.buffer.auxKey.Value[0])
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	pOut.CopyFrom(ct.Value[0].Value[0].Value[0])
	e.SingleKeyEncryptor.PolyEvaluator.ShortFourierPolyMulSubPolyAssign(ct.Value[0].Value[0].Value[1], e.buffer.auxFourierKey.Value[0], pOut)
	for i := 0; i < e.Parameters.PolyDegree(); i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParameters.LogFirstBaseQ())
	}
}
