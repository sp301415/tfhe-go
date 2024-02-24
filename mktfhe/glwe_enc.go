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
	e.BaseEncryptor.BinarySampler.SampleSliceAssign(e.buffer.auxKey.Value[0].Coeffs)
	e.BaseEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.BaseEncryptor.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.ScaledBase(i), ctOut.Value[0].Value[i].Value[0])
		e.BaseEncryptor.FourierEvaluator.PolyMulBinarySubAssign(e.buffer.auxFourierKey.Value[0], e.CRS[i], ctOut.Value[0].Value[i].Value[0])
		e.BaseEncryptor.GaussianSampler.SampleSliceAddAssign(e.Parameters.GLWEStdDev(), ctOut.Value[0].Value[i].Value[0].Coeffs)
	}

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.BaseEncryptor.PolyEvaluator.ScalarMulAssign(e.buffer.auxKey.Value[0], ctOut.GadgetParameters.ScaledBase(i), ctOut.Value[1].Value[i].Value[0])
		e.BaseEncryptor.EncryptGLWEBody(ctOut.Value[1].Value[i])
	}
}
