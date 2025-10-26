package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/sp301415/tfhe-go/tfhe"
)

// UniEncrypt encrypts integer messages to UniEncryption.
func (e *Encryptor[T]) UniEncrypt(messages []int, gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	ctOut := NewUniEncryption(e.Params, gadgetParams)
	e.UniEncryptTo(ctOut, messages, gadgetParams)
	return ctOut
}

// UniEncryptTo encrypts integer messages to UniEncryption and writes it to ctOut.
func (e *Encryptor[T]) UniEncryptTo(ctOut UniEncryption[T], messages []int, gadgetParams tfhe.GadgetParameters[T]) {
	length := num.Min(e.Params.PolyRank(), len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.MessageModulus()
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.UniEncryptPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// UniEncryptPoly encrypts polynomial to UniEncryption.
func (e *Encryptor[T]) UniEncryptPoly(p poly.Poly[T], gadgetParams tfhe.GadgetParameters[T]) UniEncryption[T] {
	ctOut := NewUniEncryption(e.Params, gadgetParams)
	e.UniEncryptPolyTo(ctOut, p)
	return ctOut
}

// UniEncryptPolyTo encrypts polynomial to UniEncryption and writes it to ctOut.
func (e *Encryptor[T]) UniEncryptPolyTo(ctOut UniEncryption[T], p poly.Poly[T]) {
	e.SubEncryptor.BinarySampler.SamplePolyTo(e.buf.auxKey.Value[0])
	e.SubEncryptor.FFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	for i := 0; i < ctOut.GadgetParams.Level(); i++ {
		ctOut.Value[0].Value[i].Value[1].CopyFrom(e.CRS[i])
		e.SubEncryptor.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[0].Value[i].Value[0], p, ctOut.GadgetParams.BaseQ(i))

		e.SubEncryptor.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ctOut.Value[0].Value[i].Value[0], ctOut.Value[0].Value[i].Value[1], e.buf.auxFourierKey.Value[0])
		e.SubEncryptor.GaussianSampler.SamplePolyAddTo(ctOut.Value[0].Value[i].Value[0], e.Params.GLWEStdDevQ())
	}

	for i := 0; i < ctOut.GadgetParams.Level(); i++ {
		e.SubEncryptor.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[1].Value[i].Value[0], e.buf.auxKey.Value[0], ctOut.GadgetParams.BaseQ(i))
		e.SubEncryptor.EncryptGLWEBody(ctOut.Value[1].Value[i])
	}
}

// UniDecrypt decrypts UniEncryption to integer messages.
func (e *Encryptor[T]) UniDecrypt(ct UniEncryption[T]) []int {
	messagesOut := make([]int, e.Params.PolyRank())
	e.UniDecryptTo(messagesOut, ct)
	return messagesOut
}

// UniDecryptTo decrypts UniEncryption to integer messages and writes it to messagesOut.
func (e *Encryptor[T]) UniDecryptTo(messagesOut []int, ct UniEncryption[T]) {
	e.UniDecryptPolyTo(e.buf.ptGLWE.Value, ct)

	length := num.Min(e.Params.PolyRank(), len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buf.ptGLWE.Value.Coeffs[i] % e.Params.MessageModulus())
	}
}

// UniDecryptPoly decrypts UniEncryption to polynomial.
func (e *Encryptor[T]) UniDecryptPoly(ct UniEncryption[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Params.PolyRank())
	e.UniDecryptPolyTo(pOut, ct)
	return pOut
}

// UniDecryptPolyTo decrypts UniEncryption to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) UniDecryptPolyTo(pOut poly.Poly[T], ct UniEncryption[T]) {
	e.SubEncryptor.DecryptGLevPolyTo(e.buf.auxKey.Value[0], ct.Value[1])
	e.SubEncryptor.FFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	pOut.CopyFrom(ct.Value[0].Value[0].Value[0])
	e.SubEncryptor.PolyEvaluator.ShortFFTPolyMulSubPolyTo(pOut, ct.Value[0].Value[0].Value[1], e.buf.auxFourierKey.Value[0])
	for i := 0; i < e.Params.PolyRank(); i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParams.LogFirstBaseQ())
	}
}
