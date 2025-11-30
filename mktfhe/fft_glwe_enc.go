package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// FFTUniEncrypt encrypts integer messages to FFTUniEncryption.
func (e *Encryptor[T]) FFTUniEncrypt(messages []int, gadgetParams tfhe.GadgetParameters[T]) FFTUniEncryption[T] {
	ctOut := NewFFTUniEncryption(e.Params, gadgetParams)
	e.FFTUniEncryptTo(ctOut, messages, gadgetParams)
	return ctOut
}

// FFTUniEncryptTo encrypts integer messages to FFTUniEncryption and writes it to ctOut.
func (e *Encryptor[T]) FFTUniEncryptTo(ctOut FFTUniEncryption[T], messages []int, gadgetParams tfhe.GadgetParameters[T]) {
	length := num.Min(e.Params.PolyRank(), len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.MessageModulus()
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.FFTUniEncryptPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// FFTUniEncryptPoly encrypts polynomial to FFTUniEncryption.
func (e *Encryptor[T]) FFTUniEncryptPoly(p poly.Poly[T], gadgetParams tfhe.GadgetParameters[T]) FFTUniEncryption[T] {
	ctOut := NewFFTUniEncryption(e.Params, gadgetParams)
	e.FFTUniEncryptPolyTo(ctOut, p)
	return ctOut
}

// FFTUniEncryptPolyTo encrypts polynomial to FFTUniEncryption and writes it to ctOut.
func (e *Encryptor[T]) FFTUniEncryptPolyTo(ctOut FFTUniEncryption[T], p poly.Poly[T]) {
	e.SubEncryptor.BinarySampler.SamplePolyTo(e.buf.auxKey.Value[0])
	e.SubEncryptor.FwdFFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	for i := 0; i < ctOut.GadgetParams.Level(); i++ {
		e.buf.ctSubGLWE.Value[1].CopyFrom(e.CRS[i])
		e.SubEncryptor.PolyEvaluator.ScalarMulPolyTo(e.buf.ctSubGLWE.Value[0], p, ctOut.GadgetParams.BaseQ(i))

		e.SubEncryptor.PolyEvaluator.ShortFFTPolyMulAddPolyTo(e.buf.ctSubGLWE.Value[0], e.buf.ctSubGLWE.Value[1], e.buf.auxFourierKey.Value[0])
		e.SubEncryptor.GaussianSampler.SamplePolyAddTo(e.buf.ctSubGLWE.Value[0], e.Params.GLWEStdDevQ())

		e.SubEncryptor.FwdFFTGLWECiphertextTo(ctOut.Value[0].Value[i], e.buf.ctSubGLWE)
	}

	for i := 0; i < ctOut.GadgetParams.Level(); i++ {
		e.SubEncryptor.PolyEvaluator.ScalarMulPolyTo(e.buf.ctSubGLWE.Value[0], e.buf.auxKey.Value[0], ctOut.GadgetParams.BaseQ(i))
		e.SubEncryptor.EncryptGLWEBody(e.buf.ctSubGLWE)
		e.SubEncryptor.FwdFFTGLWECiphertextTo(ctOut.Value[1].Value[i], e.buf.ctSubGLWE)
	}
}

// FFTUniDecrypt decrypts FFTUniEncryption to integer messages.
func (e *Encryptor[T]) FFTUniDecrypt(ct FFTUniEncryption[T]) []int {
	messages := make([]int, e.Params.PolyRank())
	e.FFTUniDecryptTo(messages, ct)
	return messages
}

// FFTUniDecryptTo decrypts FFTUniEncryption to integer messages and writes it to messagesOut.
func (e *Encryptor[T]) FFTUniDecryptTo(messagesOut []int, ct FFTUniEncryption[T]) {
	e.FFTUniDecryptPolyTo(e.buf.ptGLWE.Value, ct)

	length := num.Min(e.Params.PolyRank(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buf.ptGLWE.Value.Coeffs[i] % e.Params.MessageModulus())
	}
}

// FFTUniDecryptPoly decrypts FFTUniEncryption to polynomial.
func (e *Encryptor[T]) FFTUniDecryptPoly(ct FFTUniEncryption[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Params.PolyRank())
	e.FFTUniDecryptPolyTo(pOut, ct)
	return pOut
}

// FFTUniDecryptPolyTo decrypts FFTUniEncryption to polynomial and writes it to pOut.
func (e *Encryptor[T]) FFTUniDecryptPolyTo(pOut poly.Poly[T], ct FFTUniEncryption[T]) {
	e.SubEncryptor.DecryptFFTGLevPolyTo(e.buf.auxKey.Value[0], ct.Value[1])
	e.SubEncryptor.FwdFFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	e.SubEncryptor.InvFFTGLWECiphertextTo(e.buf.ctSubGLWE, ct.Value[0].Value[0])
	pOut.CopyFrom(e.buf.ctSubGLWE.Value[0])
	e.SubEncryptor.PolyEvaluator.ShortFFTPolyMulSubPolyTo(pOut, e.buf.ctSubGLWE.Value[1], e.buf.auxFourierKey.Value[0])
	for i := 0; i < e.Params.PolyRank(); i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParams.LogFirstBaseQ())
	}
}
