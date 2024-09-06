package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FourierUniEncrypt encrypts integer messages to FourierUniEncryption.
func (e *Encryptor[T]) FourierUniEncrypt(messages []int, gadgetParams tfhe.GadgetParameters[T]) FourierUniEncryption[T] {
	ctOut := NewFourierUniEncryption(e.Parameters, gadgetParams)
	e.FourierUniEncryptAssign(messages, gadgetParams, ctOut)
	return ctOut
}

// FourierUniEncryptAssign encrypts integer messages to FourierUniEncryption and writes it to ctOut.
func (e *Encryptor[T]) FourierUniEncryptAssign(messages []int, gadgetParams tfhe.GadgetParameters[T], ctOut FourierUniEncryption[T]) {
	length := num.Min(e.Parameters.PolyDegree(), len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.MessageModulus()
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.FourierUniEncryptPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// FourierUniEncryptPlaintext encrypts GLWE plaintext to FourierUniEncryption.
func (e *Encryptor[T]) FourierUniEncryptPlaintext(pt tfhe.GLWEPlaintext[T], gadgetParams tfhe.GadgetParameters[T]) FourierUniEncryption[T] {
	ct := NewFourierUniEncryption(e.Parameters, gadgetParams)
	e.FourierUniEncryptPlaintextAssign(pt, ct)
	return ct
}

// FourierUniEncryptPlaintextAssign encrypts GLWE plaintext to FourierUniEncryption and writes it to ctOut.
func (e *Encryptor[T]) FourierUniEncryptPlaintextAssign(pt tfhe.GLWEPlaintext[T], ctOut FourierUniEncryption[T]) {
	e.SingleKeyEncryptor.BinarySampler.SampleSliceAssign(e.buffer.auxKey.Value[0].Coeffs)
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.buffer.ctGLWESingle.Value[1].CopyFrom(e.CRS[i])
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWESingle.Value[0])

		e.SingleKeyEncryptor.Evaluator.BinaryFourierMulAddAssign(e.buffer.ctGLWESingle.Value[1], e.buffer.auxFourierKey.Value[0], e.buffer.ctGLWESingle.Value[0])
		e.SingleKeyEncryptor.GaussianSampler.SampleSliceAddAssign(e.Parameters.GLWEStdDevQ(), e.buffer.ctGLWESingle.Value[0].Coeffs)

		e.SingleKeyEncryptor.ToFourierGLWECiphertextAssign(e.buffer.ctGLWESingle, ctOut.Value[0].Value[i])
	}

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulAssign(e.buffer.auxKey.Value[0], ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWESingle.Value[0])
		e.SingleKeyEncryptor.EncryptGLWEBody(e.buffer.ctGLWESingle)
		e.SingleKeyEncryptor.ToFourierGLWECiphertextAssign(e.buffer.ctGLWESingle, ctOut.Value[1].Value[i])
	}
}

// FourierUniDecrypt decrypts FourierUniEncryption to integer messages.
func (e *Encryptor[T]) FourierUniDecrypt(ct FourierUniEncryption[T]) []int {
	messages := make([]int, e.Parameters.PolyDegree())
	e.FourierUniDecryptAssign(ct, messages)
	return messages
}

// FourierUniDecryptAssign decrypts FourierUniEncryption to integer messages and writes it to messagesOut.
func (e *Encryptor[T]) FourierUniDecryptAssign(ct FourierUniEncryption[T], messagesOut []int) {
	e.FourierUniDecryptPlaintextAssign(ct, e.buffer.ptGLWE)

	length := num.Min(e.Parameters.PolyDegree(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(num.DivRoundBits(e.buffer.ptGLWE.Value.Coeffs[i], ct.GadgetParameters.LastBaseQLog()) % e.Parameters.MessageModulus())
	}
}

// FourierUniDecryptPlaintext decrypts FourierUniEncryption to GLWE plaintext.
func (e *Encryptor[T]) FourierUniDecryptPlaintext(ct FourierUniEncryption[T]) tfhe.GLWEPlaintext[T] {
	pt := tfhe.NewGLWEPlaintext(e.Parameters.Parameters)
	e.FourierUniDecryptPlaintextAssign(ct, pt)
	return pt
}

// FourierUniDecryptPlaintextAssign decrypts FourierUniEncryption to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) FourierUniDecryptPlaintextAssign(ct FourierUniEncryption[T], ptOut tfhe.GLWEPlaintext[T]) {
	e.SingleKeyEncryptor.DecryptFourierGLevPlaintextAssign(ct.Value[1], tfhe.GLWEPlaintext[T]{Value: e.buffer.auxKey.Value[0]})
	for i := 0; i < e.Parameters.PolyDegree(); i++ {
		e.buffer.auxKey.Value[0].Coeffs[i] = num.DivRoundBits(e.buffer.auxKey.Value[0].Coeffs[i], ct.GadgetParameters.LastBaseQLog()) & (1<<ct.GadgetParameters.BaseLog() - 1)
	}
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	e.SingleKeyEncryptor.ToGLWECiphertextAssign(ct.Value[0].Value[ct.GadgetParameters.Level()-1], e.buffer.ctGLWESingle)
	ptOut.Value.CopyFrom(e.buffer.ctGLWESingle.Value[0])
	e.SingleKeyEncryptor.Evaluator.BinaryFourierMulSubAssign(e.buffer.ctGLWESingle.Value[1], e.buffer.auxFourierKey.Value[0], ptOut.Value)
}
