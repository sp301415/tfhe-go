package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// mulFourierGLWEKeyAssign computes pOut = p * fsk, where fsk is a Fourier Transform of auxillary GLWE key.
func (e *PublicEncryptor[T]) mulFourierGLWEKeyAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpGLWESplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpGLWESplit, e.buffer.pGLWESplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pGLWESplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpGLWESplit, e.buffer.pGLWESplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pGLWESplit.Coeffs[i] << bits) << bits
	}
}

// mulFourierGLWEKeyAssign computes pOut += p * fsk, where fsk is a Fourier Transform of auxillary GLWE key.
func (e *PublicEncryptor[T]) mulFourierGLWEKeyAddAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAddAssignUnsafe(e.buffer.fpGLWESplit, pOut)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpGLWESplit, e.buffer.pGLWESplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += e.buffer.pGLWESplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.polyDegree; i++ {
		e.buffer.pGLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pGLWESplit, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.MulAssign(e.buffer.fpGLWESplit, fsk, e.buffer.fpGLWESplit)
	e.GLWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpGLWESplit, e.buffer.pGLWESplit)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		pOut.Coeffs[i] += (e.buffer.pGLWESplit.Coeffs[i] << bits) << bits
	}
}

// EncryptGLWE encodes and encrypts integer messages to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWE(messages []int) GLWECiphertext[T] {
	ctOut := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEAssign(messages, ctOut)
	return ctOut
}

// EncryptGLWEAssign encodes and encrypts integer messages to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEAssign(messages []int, ctOut GLWECiphertext[T]) {
	e.EncodeGLWEAssign(messages, e.buffer.ptGLWE)
	e.EncryptGLWEPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGLWEPlaintext encrypts GLWE plaintext to GLWE ciphertext.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintext(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLWEPlaintextAssign encrypts GLWE plaintext to GLWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLWEPlaintextAssign(pt GLWEPlaintext[T], ctOut GLWECiphertext[T]) {
	ctOut.Value[0].CopyFrom(pt.Value)
	e.EncryptGLWEBody(ctOut)
}

// EncryptGLWEBody encrypts the value in the body of GLWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptGLWEBody(ct GLWECiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.BinarySampler.SampleSliceAssign(e.buffer.auxGLWEKey.Value[i].Coeffs)
		e.GLWEFourierEvaluator.ToFourierPolyAssign(e.buffer.auxGLWEKey.Value[i], e.buffer.auxFourierGLWEKey.Value[i])
	}

	for j := 1; j < e.Parameters.glweDimension+1; j++ {
		e.mulFourierGLWEKeyAssign(e.PublicKey.GLWEPublicKey.Value[0].Value[j], e.buffer.auxFourierGLWEKey.Value[0], ct.Value[j])
	}
	e.mulFourierGLWEKeyAddAssign(e.PublicKey.GLWEPublicKey.Value[0].Value[0], e.buffer.auxFourierGLWEKey.Value[0], ct.Value[0])

	for i := 1; i < e.Parameters.glweDimension; i++ {
		for j := 0; j < e.Parameters.glweDimension+1; j++ {
			e.mulFourierGLWEKeyAddAssign(e.PublicKey.GLWEPublicKey.Value[1].Value[j], e.buffer.auxFourierGLWEKey.Value[i], ct.Value[j])
		}
	}

	for j := 0; j < e.Parameters.glweDimension+1; j++ {
		e.GaussianSampler.SampleSliceAddAssign(e.Parameters.glweStdDev, ct.Value[j].Coeffs)
	}
}

// EncryptGLev encrypts integer message to GLev ciphertext.
func (e *PublicEncryptor[T]) EncryptGLev(messages []int, gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevAssign(messages, ct)
	return ct
}

// EncryptGLevAssign encrypts integer message to GLev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLevAssign(messages []int, ctOut GLevCiphertext[T]) {
	length := num.Min(e.Parameters.polyDegree, len(messages))
	for i := 0; i < length; i++ {
		e.buffer.ptGLWE.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	vec.Fill(e.buffer.ptGLWE.Value.Coeffs[length:], 0)

	e.EncryptGLevPlaintextAssign(e.buffer.ptGLWE, ctOut)
}

// EncryptGLevPlaintext encrypts GLWE plaintext to GLev ciphertext.
func (e *PublicEncryptor[T]) EncryptGLevPlaintext(pt GLWEPlaintext[T], gadgetParams GadgetParameters[T]) GLevCiphertext[T] {
	ct := NewGLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptGLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptGLevPlaintextAssign encrypts GLWE plaintext to GLev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptGLevPlaintextAssign(pt GLWEPlaintext[T], ctOut GLevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		e.GLWEPolyEvaluator.ScalarMulAssign(pt.Value, ctOut.GadgetParameters.ScaledBase(i), ctOut.Value[i].Value[0])
		e.EncryptGLWEBody(ctOut.Value[i])
	}
}
