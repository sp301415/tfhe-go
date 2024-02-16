package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// mulFourierGLWEKeyAssign computes pOut = p * fsk, where fsk is a Fourier Transform of GLWE key.
func (e *Encryptor[T]) mulFourierGLWEKeyAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

// mulFourierGLWEKeyAddAssign computes pOut += p * fsk, where fsk is a Fourier Transform of GLWE key.
func (e *Encryptor[T]) mulFourierGLWEKeyAddAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

// mulFourierGLWEKeySubAssign computes pOut -= p * fsk, where fsk is a Fourier Transform of GLWE key.
func (e *Encryptor[T]) mulFourierGLWEKeySubAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolySubAssignUnsafe(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] -= e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fsk, e.buffer.fpSplit)
	e.FourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] -= (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

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
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.UniformSampler.SampleSliceAssign(ct.Value[i].Coeffs)
	}

	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.mulFourierGLWEKeySubAssign(ct.Value[i+1], e.SecretKey.FourierGLWEKey.Value[i], ct.Value[0])
	}

	e.GaussianSampler.SampleSliceAddAssign(e.Parameters.glweStdDev, ct.Value[0].Coeffs)
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	e.DecryptGLWEPlaintextAssign(ct, e.buffer.ptGLWE)
	return e.DecodeGLWE(e.buffer.ptGLWE)
}

// DecryptGLWEAssign decrypts and decodes GLWE ciphertext to integer message and writes it to messagesOut.
func (e *Encryptor[T]) DecryptGLWEAssign(ct GLWECiphertext[T], messagesOut []int) {
	e.DecryptGLWEPlaintextAssign(ct, e.buffer.ptGLWE)
	e.DecodeGLWEAssign(e.buffer.ptGLWE, messagesOut)
}

// DecryptGLWEPlaintext decrypts GLWE ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGLWEPlaintext(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEPlaintextAssign(ct, pt)
	return pt
}

// DecryptGLWEPlaintextAssign decrypts GLWE ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptGLWEPlaintextAssign(ct GLWECiphertext[T], ptOut GLWEPlaintext[T]) {
	ptOut.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.mulFourierGLWEKeyAddAssign(ct.Value[i+1], e.SecretKey.FourierGLWEKey.Value[i], ptOut.Value)
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

	e.EncryptGLevPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGLevPlaintext encrypts GLWE plaintext to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLevPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLevPlaintextAssign encrypts GLWE plaintext to GLev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevPlaintextAssign(pt GLWEPlaintext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.ScaledBase(i), ctOut.Value[i].Value[0])
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
	e.DecryptGLevPlaintextAssign(ct, e.buffer.ptGLWE)

	length := num.Min(e.Parameters.polyDegree, len(messagesOut))
	for i := 0; i < length; i++ {
		messagesOut[i] = int(num.RoundRatioBits(e.buffer.ptGLWE.Value.Coeffs[i], ct.GadgetParameters.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
}

// DecryptGLevPlaintext decrypts GLev ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGLevPlaintext(ct GLevCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevPlaintextAssign(ct, pt)
	return pt
}

// DecryptGLevPlaintextAssign decrypts GLev ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptGLevPlaintextAssign(ct GLevCiphertext[T], ptOut GLWEPlaintext[T]) {
	ctLastLevel := ct.Value[ct.GadgetParameters.level-1]
	e.DecryptGLWEPlaintextAssign(ctLastLevel, ptOut)
}

// EncryptGGSW encrypts integer message to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSW(messages []int, gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptGGSWPlaintext(pt, gadgetParams)
}

// EncryptGGSWAssign encrypts integer message to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWAssign(messages []int, ctOut GGSWCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGGSWPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGGSWPlaintext encrypts GLWE plaintext to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSWPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ct := NewGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptGGSWPlaintextAssign(pt, ct)
	return ct
}

// EncryptGGSWPlaintextAssign encrypts GLWE plaintext to GGSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGGSWPlaintextAssign(pt GLWEPlaintext[T], ctOut GGSWCiphertext[T]) {
	e.EncryptGLevPlaintextAssign(pt, ctOut.Value[0])
	for i := 1; i < e.Parameters.glweDimension+1; i++ {
		e.mulFourierGLWEKeyAssign(pt.Value, e.SecretKey.FourierGLWEKey.Value[i-1], e.buffer.ptGGSW)
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			e.PolyEvaluator.ScalarMulAssign(e.buffer.ptGGSW, ctOut.GadgetParameters.ScaledBase(j), ctOut.Value[i].Value[j].Value[0])
			e.EncryptGLWEBody(ctOut.Value[i].Value[j])
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

// DecryptGGSWPlaintext decrypts GGSW ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGGSWPlaintext(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptGLevPlaintext(ct.Value[0])
}

// DecryptGGSWPlaintextAssign decrypts GGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptGGSWPlaintextAssign(ct GGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptGLevPlaintextAssign(ct.Value[0], ptOut)
}
