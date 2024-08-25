package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
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

	e.UniEncryptPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// UniEncryptPlaintext encrypts GLWE plaintext to UniEncryption.
func (e *Encryptor[T]) UniEncryptPlaintext(pt tfhe.GLWEPlaintext[T], gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	ct := NewUniEncryption(e.Parameters, gadgetParams)
	e.UniEncryptPlaintextAssign(pt, ct)
	return ct
}

// UniEncryptPlaintextAssign encrypts GLWE plaintext to UniEncryption and writes it to ctOut.
func (e *Encryptor[T]) UniEncryptPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut UniEncryption[T]) {
	e.SingleKeyEncryptor.BinarySampler.SampleSliceAssign(e.buffer.auxKey.Value[0].Coeffs)
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		ctOut.Value[0].Value[i].Value[1].CopyFrom(e.CRS[i])
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.BaseQ(i), ctOut.Value[0].Value[i].Value[0])

		e.SingleKeyEncryptor.FourierEvaluator.PolyMulBinaryAddAssign(e.buffer.auxFourierKey.Value[0], ctOut.Value[0].Value[i].Value[1], ctOut.Value[0].Value[i].Value[0])
		e.SingleKeyEncryptor.GaussianSampler.SampleSliceAddAssign(e.Parameters.GLWEStdDevQ(), ctOut.Value[0].Value[i].Value[0].Coeffs)
	}

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulAssign(e.buffer.auxKey.Value[0], ctOut.GadgetParameters.BaseQ(i), ctOut.Value[1].Value[i].Value[0])
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
	e.UniDecryptPlaintextAssign(ct, e.buffer.ptGLWE)

	length := num.Min(e.Parameters.PolyDegree(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(num.DivRoundBits(e.buffer.ptGLWE.Value.Coeffs[i], ct.GadgetParameters.LastBaseQLog()) % e.Parameters.MessageModulus())
	}
}

// UniDecryptPlaintext decrypts UniEncryption to GLWE plaintext.
func (e *Encryptor[T]) UniDecryptPlaintext(ct UniEncryption[T]) tfhe.GLWEPlaintext[T] {
	pt := tfhe.NewGLWEPlaintext(e.Parameters.Parameters)
	e.UniDecryptPlaintextAssign(ct, pt)
	return pt
}

// UniDecryptPlaintextAssign decrypts UniEncryption to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) UniDecryptPlaintextAssign(ct UniEncryption[T], ptOut tfhe.GLWEPlaintext[T]) {
	e.SingleKeyEncryptor.DecryptGLevPlaintextAssign(ct.Value[1], tfhe.GLWEPlaintext[T]{Value: e.buffer.auxKey.Value[0]})
	for i := 0; i < e.Parameters.PolyDegree(); i++ {
		e.buffer.auxKey.Value[0].Coeffs[i] = num.DivRoundBits(e.buffer.auxKey.Value[0].Coeffs[i], ct.GadgetParameters.LastBaseQLog()) & (1<<ct.GadgetParameters.BaseLog() - 1)
	}
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	ptOut.Value.CopyFrom(ct.Value[0].Value[ct.GadgetParameters.Level()-1].Value[0])
	e.SingleKeyEncryptor.FourierEvaluator.PolyMulBinarySubAssign(e.buffer.auxFourierKey.Value[0], ct.Value[0].Value[ct.GadgetParameters.Level()-1].Value[1], ptOut.Value)
}
