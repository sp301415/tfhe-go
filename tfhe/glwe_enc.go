package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// mulFourierGLWEKeyAssign multiplies p with Fourier GLWE key element fp.
func (e *Encryptor[T]) mulFourierGLWEKeyAssign(p0 poly.Poly[T], fp poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p0.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

// mulFourierGLWEKeyAddAssign multiplies p with Fourier GLWE key element fp and adds it to pOut.
func (e *Encryptor[T]) mulFourierGLWEKeyAddAssign(p0 poly.Poly[T], fp poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p0.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAddAssign(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

// mulFourierGLWEKeySubAssign multiplies p with Fourier GLWE key element fp and subtracts it from pOut.
func (e *Encryptor[T]) mulFourierGLWEKeySubAssign(p0 poly.Poly[T], fp poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = p0.Coeffs[i] & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolySubAssign(e.buffer.fpSplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) & mask
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] -= e.buffer.pSplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pSplit.Coeffs[i] = (p0.Coeffs[i] >> bits) >> bits
	}
	e.FourierEvaluator.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fpSplit)
	e.FourierEvaluator.MulAssign(e.buffer.fpSplit, fp, e.buffer.fpSplit)
	e.FourierEvaluator.ToStandardPolyAssign(e.buffer.fpSplit, e.buffer.pSplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] -= (e.buffer.pSplit.Coeffs[i] << bits) << bits
	}
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	return e.EncryptGLWEPlaintext(e.EncodeGLWE(messages))
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *Encryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ctOut)
	return ctOut
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
		e.uniformSampler.SampleSliceAssign(ct.Value[i].Coeffs)
	}
	e.glweSampler.SampleSliceAddAssign(ct.Value[0].Coeffs)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.mulFourierGLWEKeySubAssign(ct.Value[i+1], e.SecretKey.FourierGLWEKey.Value[i], ct.Value[0])
	}
}

// DecryptGLWE decrypts and decodes GLWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWEPlaintext(ct))
}

// DecryptGLWEPlaintext decrypts GLWE ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGLWEPlaintext(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEPlaintextAssign(ct, ptOut)
	return ptOut
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
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptGLevPlaintext(pt, gadgetParams)
}

// EncryptGLevPlaintext encrypts GLWE plaintext to GLev ciphertext.
func (e *Encryptor[T]) EncryptGLevPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ctOut := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptGLevPlaintextAssign encrypts GLWE plaintext to GLev ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) EncryptGLevPlaintextAssign(pt GLWEPlaintext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.PolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.ScaledBase(i), ctOut.Value[i].Value[0])
		e.EncryptGLWEBody(ctOut.Value[i])
	}
}

// DecryptGLev decrypts GLev ciphertext to integer message.
func (e *Encryptor[T]) DecryptGLev(ct GLevCiphertext[T]) []int {
	pt := e.DecryptGLevPlaintext(ct)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatioBits(pt.Value.Coeffs[i], ct.GadgetParameters.LastScaledBaseLog()) % e.Parameters.messageModulus)
	}
	return messages
}

// DecryptGLevPlaintext decrypts GLev ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGLevPlaintext(ct GLevCiphertext[T]) GLWEPlaintext[T] {
	ptOut := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevPlaintextAssign(ct, ptOut)
	return ptOut
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

// EncryptGGSWPlaintext encrypts GLWE plaintext to GGSW ciphertext.
func (e *Encryptor[T]) EncryptGGSWPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) GGSWCiphertext[T] {
	ctOut := NewGGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptGGSWPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptGGSWPlaintextAssign encrypts GLWE plaintext to GGSW ciphertext, and writes it to ctOut.
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

// DecryptGGSWPlaintext decrypts GGSW ciphertext to GLWE plaintext.
func (e *Encryptor[T]) DecryptGGSWPlaintext(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	return e.DecryptGLevPlaintext(ct.Value[0])
}

// DecryptGGSWPlaintextAssign decrypts GGSW ciphertext to GLWE plaintext and writes it to ptOut.
func (e *Encryptor[T]) DecryptGGSWPlaintextAssign(ct GGSWCiphertext[T], ptOut GLWEPlaintext[T]) {
	e.DecryptGLevPlaintextAssign(ct.Value[0], ptOut)
}
