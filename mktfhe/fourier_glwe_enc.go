package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
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

	e.FourierUniEncryptPolyAssign(e.buffer.ptGLWE.Value, ctOut)
}

// FourierUniEncryptPoly encrypts polynomial to FourierUniEncryption.
func (e *Encryptor[T]) FourierUniEncryptPoly(p poly.Poly[T], gadgetParams tfhe.GadgetParameters[T]) FourierUniEncryption[T] {
	ctOut := NewFourierUniEncryption(e.Parameters, gadgetParams)
	e.FourierUniEncryptPolyAssign(p, ctOut)
	return ctOut
}

// FourierUniEncryptPolyAssign encrypts polynomial to FourierUniEncryption and writes it to ctOut.
func (e *Encryptor[T]) FourierUniEncryptPolyAssign(p poly.Poly[T], ctOut FourierUniEncryption[T]) {
	e.SingleKeyEncryptor.BinarySampler.SamplePolyAssign(e.buffer.auxKey.Value[0])
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.buffer.ctGLWESingle.Value[1].CopyFrom(e.CRS[i])
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulPolyAssign(p, ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWESingle.Value[0])

		e.SingleKeyEncryptor.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(e.buffer.ctGLWESingle.Value[1], e.buffer.auxFourierKey.Value[0], e.buffer.ctGLWESingle.Value[0])
		e.SingleKeyEncryptor.GaussianSampler.SamplePolyAddAssign(e.Parameters.GLWEStdDevQ(), e.buffer.ctGLWESingle.Value[0])

		e.SingleKeyEncryptor.ToFourierGLWECiphertextAssign(e.buffer.ctGLWESingle, ctOut.Value[0].Value[i])
	}

	for i := 0; i < ctOut.GadgetParameters.Level(); i++ {
		e.SingleKeyEncryptor.PolyEvaluator.ScalarMulPolyAssign(e.buffer.auxKey.Value[0], ctOut.GadgetParameters.BaseQ(i), e.buffer.ctGLWESingle.Value[0])
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
	e.FourierUniDecryptPolyAssign(ct, e.buffer.ptGLWE.Value)

	length := num.Min(e.Parameters.PolyDegree(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buffer.ptGLWE.Value.Coeffs[i] % e.Parameters.MessageModulus())
	}
}

// FourierUniDecryptPoly decrypts FourierUniEncryption to polynomial.
func (e *Encryptor[T]) FourierUniDecryptPoly(ct FourierUniEncryption[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Parameters.PolyDegree())
	e.FourierUniDecryptPolyAssign(ct, pOut)
	return pOut
}

// FourierUniDecryptPolyAssign decrypts FourierUniEncryption to polynomial and writes it to pOut.
func (e *Encryptor[T]) FourierUniDecryptPolyAssign(ct FourierUniEncryption[T], pOut poly.Poly[T]) {
	e.SingleKeyEncryptor.DecryptFourierGLevPolyAssign(ct.Value[1], e.buffer.auxKey.Value[0])
	e.SingleKeyEncryptor.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	e.SingleKeyEncryptor.ToGLWECiphertextAssign(ct.Value[0].Value[0], e.buffer.ctGLWESingle)
	pOut.CopyFrom(e.buffer.ctGLWESingle.Value[0])
	e.SingleKeyEncryptor.PolyEvaluator.ShortFourierPolyMulSubPolyAssign(e.buffer.ctGLWESingle.Value[1], e.buffer.auxFourierKey.Value[0], pOut)
	for i := 0; i < e.Parameters.PolyDegree(); i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParameters.LogFirstBaseQ())
	}
}
