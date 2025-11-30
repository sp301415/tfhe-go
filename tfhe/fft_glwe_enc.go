package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptFFTGLWE encodes and encrypts integer messages to FFTGLWE ciphertext.
func (e *Encryptor[T]) EncryptFFTGLWE(messages []int) FFTGLWECiphertext[T] {
	return e.EncryptFFTGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptFFTGLWETo encrypts and encrypts integer messages to FFTGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLWETo(ctOut FFTGLWECiphertext[T], messages []int) {
	e.EncryptFFTGLWEPlaintextTo(ctOut, e.EncodeGLWE(messages))
}

// EncryptFFTGLWEPlaintext encrypts GLWE plaintext to FFTGLWE ciphertext.
func (e *Encryptor[T]) EncryptFFTGLWEPlaintext(pt GLWEPlaintext[T]) FFTGLWECiphertext[T] {
	ctOut := NewFFTGLWECiphertext(e.Params)
	e.EncryptFFTGLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptFFTGLWEPlaintextTo encrypts GLWE plaintext to FFTGLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLWEPlaintextTo(ctOut FFTGLWECiphertext[T], pt GLWEPlaintext[T]) {
	e.EncryptGLWEPlaintextTo(e.buf.ctGLWE, pt)
	e.FwdFFTGLWECiphertextTo(ctOut, e.buf.ctGLWE)
}

// DecryptFFTGLWE decrypts and decodes FFTGLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptFFTGLWE(ct FFTGLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptFFTGLWEPhase(ct))
}

// DecryptFFTGLWETo decrypts and decodes FFTGLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFFTGLWETo(messagesOut []int, ct FFTGLWECiphertext[T]) {
	e.DecodeGLWETo(messagesOut, e.DecryptFFTGLWEPhase(ct))
}

// DecryptFFTGLWEPhase decrypts FFTGLWE ciphertext to GLWE plaintext including errors.
func (e *Encryptor[T]) DecryptFFTGLWEPhase(ct FFTGLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Params)
	e.DecryptFFTGLWEPhaseTo(ptOut, ct)
	return ptOut
}

// DecryptFFTGLWEPhaseTo decrypts FFTGLWE ciphertext to GLWE plaintext including errors and writes it to ptOut.
func (e *Encryptor[T]) DecryptFFTGLWEPhaseTo(ptOut GLWEPlaintext[T], ct FFTGLWECiphertext[T]) {
	e.InvFFTGLWECiphertextTo(e.buf.ctGLWE, ct)
	e.DecryptGLWEPhaseTo(ptOut, e.buf.ctGLWE)
}

// EncryptFFTGLev encrypts integer message to FFTGLev ciphertext.
func (e *Encryptor[T]) EncryptFFTGLev(messages []int, gadgetParams GadgetParameters[T]) FFTGLevCiphertext[T] {
	ctOut := NewFFTGLevCiphertext(e.Params, gadgetParams)
	e.EncryptFFTGLevTo(ctOut, messages)
	return ctOut
}

// EncryptFFTGLevTo encrypts integer message to FFTGLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLevTo(ctOut FFTGLevCiphertext[T], messages []int) {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.messageModulus
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptFFTGLevPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// EncryptFFTGLevPoly encrypts polynomial to FFTGLev ciphertext.
func (e *Encryptor[T]) EncryptFFTGLevPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) FFTGLevCiphertext[T] {
	ctOut := NewFFTGLevCiphertext(e.Params, gadgetParams)
	e.EncryptFFTGLevPolyTo(ctOut, p)
	return ctOut
}

// EncryptFFTGLevPolyTo encrypts polynomial to FFTGLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGLevPolyTo(ctOut FFTGLevCiphertext[T], p poly.Poly[T]) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		e.PolyEvaluator.ScalarMulPolyTo(e.buf.ctGLWE.Value[0], p, ctOut.GadgetParams.BaseQ(i))
		e.EncryptGLWEBody(e.buf.ctGLWE)
		e.FwdFFTGLWECiphertextTo(ctOut.Value[i], e.buf.ctGLWE)
	}
}

// DecryptFFTGLev decrypts FFTGLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptFFTGLev(ct FFTGLevCiphertext[T]) []int {
	messagesOut := make([]int, e.Params.polyRank)
	e.DecryptFFTGLevTo(messagesOut, ct)
	return messagesOut
}

// DecryptFFTGLevTo decrypts FFTGLev ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFFTGLevTo(messagesOut []int, ct FFTGLevCiphertext[T]) {
	e.DecryptFFTGLevPolyTo(e.buf.ptGLWE.Value, ct)

	length := num.Min(e.Params.polyRank, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(e.buf.ptGLWE.Value.Coeffs[i] % e.Params.messageModulus)
	}
}

// DecryptFFTGLevPoly decrypts FFTGLev ciphertext to polynomial.
func (e *Encryptor[T]) DecryptFFTGLevPoly(ct FFTGLevCiphertext[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](e.Params.polyRank)
	e.DecryptFFTGLevPolyTo(pOut, ct)
	return pOut
}

// DecryptFFTGLevPolyTo decrypts FFTGLev ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptFFTGLevPolyTo(pOut poly.Poly[T], ct FFTGLevCiphertext[T]) {
	e.DecryptFFTGLWEPhaseTo(GLWEPlaintext[T]{Value: pOut}, ct.Value[0])
	for i := 0; i < e.Params.polyRank; i++ {
		pOut.Coeffs[i] = num.DivRoundBits(pOut.Coeffs[i], ct.GadgetParams.LogFirstBaseQ()) % ct.GadgetParams.base
	}
}

// EncryptFFTGGSW encrypts integer message to FFTGGSW ciphertext.
func (e *Encryptor[T]) EncryptFFTGGSW(messages []int, gadgetParams GadgetParameters[T]) FFTGGSWCiphertext[T] {
	ctOut := NewFFTGGSWCiphertext(e.Params, gadgetParams)
	e.EncryptFFTGGSWTo(ctOut, messages)
	return ctOut
}

// EncryptFFTGGSWTo encrypts integer message to FFTGGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGGSWTo(ctOut FFTGGSWCiphertext[T], messages []int) {
	length := num.Min(e.Params.polyRank, len(messages))
	for i := 0; i < length; i++ {
		e.buf.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Params.messageModulus
	}
	vec.Fill(e.buf.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptFFTGGSWPolyTo(ctOut, e.buf.ptGLWE.Value)
}

// EncryptFFTGGSWPoly encrypts polynomial to FFTGGSW ciphertext.
func (e *Encryptor[T]) EncryptFFTGGSWPoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) FFTGGSWCiphertext[T] {
	ctOut := NewFFTGGSWCiphertext(e.Params, gadgetParams)
	e.EncryptFFTGGSWPolyTo(ctOut, p)
	return ctOut
}

// EncryptFFTGGSWPolyTo encrypts polynomial to FFTGGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptFFTGGSWPolyTo(ctOut FFTGGSWCiphertext[T], p poly.Poly[T]) {
	e.EncryptFFTGLevPolyTo(ctOut.Value[0], p)
	for i := 0; i < e.Params.glweRank; i++ {
		e.PolyEvaluator.ShortFFTPolyMulPolyTo(e.buf.ptGGSW, p, e.SecretKey.FFTGLWEKey.Value[i])
		for j := 0; j < ctOut.GadgetParams.level; j++ {
			e.PolyEvaluator.ScalarMulPolyTo(e.buf.ctGLWE.Value[0], e.buf.ptGGSW, ctOut.GadgetParams.BaseQ(j))
			e.EncryptGLWEBody(e.buf.ctGLWE)
			e.FwdFFTGLWECiphertextTo(ctOut.Value[i+1].Value[j], e.buf.ctGLWE)
		}
	}
}

// DecryptFFTGGSW decrypts FFTGGSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptFFTGGSW(ct FFTGGSWCiphertext[T]) []int {
	return e.DecryptFFTGLev(ct.Value[0])
}

// DecryptFFTGGSWTo decrypts FFTGGSW ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptFFTGGSWTo(ct FFTGGSWCiphertext[T], messagesOut []int) {
	e.DecryptFFTGLevTo(messagesOut, ct.Value[0])
}

// DecryptFFTGGSWPoly decrypts FFTGGSW ciphertext to polynomial.
func (e *Encryptor[T]) DecryptFFTGGSWPoly(ct FFTGGSWCiphertext[T]) poly.Poly[T] {
	return e.DecryptFFTGLevPoly(ct.Value[0])
}

// DecryptFFTGGSWPolyTo decrypts FFTGGSW ciphertext to polynomial and writes it to pOut.
func (e *Encryptor[T]) DecryptFFTGGSWPolyTo(ct FFTGGSWCiphertext[T], pOut poly.Poly[T]) {
	e.DecryptFFTGLevPolyTo(pOut, ct.Value[0])
}
