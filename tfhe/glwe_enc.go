package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWETo(ctOut, messages)
	return ctOut
}

// EncryptGLWETo encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWETo(ctOut GLWECiphertext[T], messages []int) {
	e.EncodeGLWETo(e.buf.ptGLWE, messages)
	e.EncryptGLWEPlaintextTo(ctOut, e.buf.ptGLWE)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Params)
	e.EncryptGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptGLWEPlaintextTo encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEPlaintextTo(ctOut GLWECiphertext[T], pt GLWEPlaintext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank; i++ {
		e.UniformSampler.SamplePolyTo(ct.Value[i+1])
		e.PolyEvaluator.ShortFFTPolyMulSubPolyTo(ct.Value[0], ct.Value[i+1], e.SecretKey.FFTGLWEKey.Value[i])
	}

	e.GaussianSampler.SamplePolyAddTo(ct.Value[0], e.Params.GLWEStdDevQ())
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	e.DecryptGLWEPhaseTo(e.buf.ptGLWE, ct)
	return e.DecodeGLWE(e.buf.ptGLWE)
}

// DecryptGLWETo decrypts and decodes GLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGLWETo(messagesOut []int, ct GLWECiphertext[T]) {
	e.DecryptGLWEPhaseTo(e.buf.ptGLWE, ct)
	e.DecodeGLWETo(messagesOut, e.buf.ptGLWE)
}

// DecryptGLWEPhase decrypts GLWE ciphertext to GLWE plaintext including errors.
func (e *Encryptor[T]) DecryptGLWEPhase(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Params)
	e.DecryptGLWEPhaseTo(ptOut, ct)
	return ptOut
}

// DecryptGLWEPhaseTo decrypts GLWE ciphertext to GLWE plaintext including errors and writes it to ptOut.
func (e *Encryptor[T]) DecryptGLWEPhaseTo(ptOut GLWEPlaintext[T], ct GLWECiphertext[T]) {
	ptOut.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Params.glweRank; i++ {
		e.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ptOut.Value, ct.Value[i+1], e.SecretKey.FFTGLWEKey.Value[i])
	}
}

// EncryptGLev encrypts integer message to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLev(messages []int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Params, gadgetParams)
	e.EncryptGLevTo(ctOut, messages)
	return ctOut
}

// EncryptGLevTo encrypts integer message to GLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevTo(ctOut GLevCiphertext[T], messages []int) {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.messageModulus
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGLevPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// EncryptGLevPoly encrypts polynomial to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLevPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Params, gadgetParams)
	e.EncryptGLevPolyTo(ctOut, p)
	return ctOut
}

// EncryptGLevPolyTo encrypts polynomial to GLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevPolyTo(ctOut GLevCiphertext[T], p poly.Poly[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[i].Value[0], p, ctOut.GadgetParams.BaseQ(i))
		e.EncryptGLWEBody(ctOut.Value[i])
	}
}

// DecryptGLev decrypts GLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLev(ct GLevCiphertext[T]) []int {
	messagesOut := make([]int, e.Params.polyRank)
	e.DecryptGLevTo(messagesOut, ct)
	return messagesOut
}

// DecryptGLevTo decrypts GLev ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGLevTo(messagesOut []int, ct GLevCiphertext[T]) {
	e.DecryptGLevPolyTo(e.buf.ptGLWE.Value, ct)

	length := num.Min(e.Params.polyRank, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buf.ptGLWE.Value.Coeffs[i] % e.Params.messageModulus)
	}
}

// DecryptGLevPoly decrypts GLev ciphertext to polynomial.
func (e *Encryptor[T]) DecryptGLevPoly(ct GLevCiphertext[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Params.polyRank)
	e.DecryptGLevPolyTo(pOut, ct)
	return pOut
}

// DecryptGLevPolyTo decrypts GLev ciphertext to poly and writes it to pOut.
func (e *Encryptor[T]) DecryptGLevPolyTo(pOut poly.Poly[T], ct GLevCiphertext[T]) {
	e.DecryptGLWEPhaseTo(GLWEPlaintext[T]{Value: pOut}, ct.Value[0])
	for i := 0; i < e.Params.polyRank; i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParams.LogFirstBaseQ()) % ct.GadgetParams.base
	}
}

// EncryptGGSW encrypts integer message to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSW(messages []int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.messageModulus
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	return e.EncryptGGSWPoly(e.buf.ptGLWE.Value, gadgetParams)
}

// EncryptGGSWTo encrypts integer message to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWTo(ctOut GGSWCiphertext[T], messages []int) {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.messageModulus
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGGSWPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// EncryptGGSWPoly encrypts polynomial to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSWPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Params, gadgetParams)
	e.EncryptGGSWPolyTo(ctOut, p)
	return ctOut
}

// EncryptGGSWPolyTo encrypts polynomial to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWPolyTo(ctOut GGSWCiphertext[T], p poly.Poly[T]) {
	e.EncryptGLevPolyTo(ctOut.Value[0], p)
	for i := 0; i < e.Params.glweRank; i++ {
		e.PolyEvaluator.ShortFFTPolyMulPolyTo(e.buf.ptGGSW, p, e.SecretKey.FFTGLWEKey.Value[i])
		for j := 0; j < ctOut.GadgetParams.level; j++ {
			e.PolyEvaluator.ScalarMulPolyTo(ctOut.Value[i+1].Value[j].Value[0], e.buf.ptGGSW, ctOut.GadgetParams.BaseQ(j))
			e.EncryptGLWEBody(ctOut.Value[i+1].Value[j])
		}
	}
}

// DecryptGGSW decrypts GGSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptGGSW(ct GGSWCiphertext[T]) []int {
	return e.DecryptGLev(ct.Value[0])
}

// DecryptGGSWTo decrypts GGSW ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGGSWTo(messagesOut []int, ct GGSWCiphertext[T]) {
	e.DecryptGLevTo(messagesOut, ct.Value[0])
}

// DecryptGGSWPoly decrypts GGSW ciphertext to polynomial.
func (e *Encryptor[T]) DecryptGGSWPoly(ct GGSWCiphertext[T]) poly.Poly[T] {
	return e.DecryptGLevPoly(ct.Value[0])
}

// DecryptGGSWPolyTo decrypts GGSW ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptGGSWPolyTo(pOut poly.Poly[T], ct GGSWCiphertext[T]) {
	e.DecryptGLevPolyTo(pOut, ct.Value[0])
}
