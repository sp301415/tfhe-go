package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// mulFourierLWEKeySubAssign computes pOut -= p * fsk, where fsk is a Fourier Transform of auxillary LWE key.
func (e *PublicEncryptor[T]) mulFourierLWEKeyAssign(p poly.Poly[T], fsk poly.FourierPoly, pOut poly.Poly[T]) {
	// We split by 22 bits.
	const bits = 22
	const mask = (1 << bits) - 1

	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		e.buffer.pLWESplit.Coeffs[i] = p.Coeffs[i] & mask
	}
	e.LWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pLWESplit, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.MulAssign(e.buffer.fpLWESplit, fsk, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpLWESplit, pOut)

	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		e.buffer.pLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) & mask
	}
	e.LWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pLWESplit, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.MulAssign(e.buffer.fpLWESplit, fsk, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpLWESplit, e.buffer.pLWESplit)
	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		pOut.Coeffs[i] += e.buffer.pLWESplit.Coeffs[i] << bits
	}

	if num.SizeT[T]() < 2*bits {
		return
	}

	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		e.buffer.pLWESplit.Coeffs[i] = (p.Coeffs[i] >> bits) >> bits
	}
	e.LWEFourierEvaluator.ToFourierPolyAssign(e.buffer.pLWESplit, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.MulAssign(e.buffer.fpLWESplit, fsk, e.buffer.fpLWESplit)
	e.LWEFourierEvaluator.ToPolyAssignUnsafe(e.buffer.fpLWESplit, e.buffer.pLWESplit)
	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		pOut.Coeffs[i] += (e.buffer.pLWESplit.Coeffs[i] << bits) << bits
	}
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEAssign encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEAssign(message int, ctOut LWECiphertext[T]) {
	e.EncryptLWEPlaintextAssign(e.EncodeLWE(message), ctOut)
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWEPlaintext(pt LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptLWEPlaintextAssign encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEPlaintextAssign(pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.BinarySampler.SampleSliceAssign(e.buffer.auxLWEKey.Coeffs)

	ct.Value[0] += vec.Dot(e.PublicKey.LWEPublicKey.Value[0].Coeffs, e.buffer.auxLWEKey.Coeffs)
	ct.Value[0] += e.GaussianSampler.Sample(e.Parameters.DefaultLWEStdDev())

	vec.ReverseInPlace(e.buffer.auxLWEKey.Coeffs)
	e.LWEFourierEvaluator.ToFourierPolyAssign(e.buffer.auxLWEKey, e.buffer.auxFourierLWEKey)

	ctMaskPoly := poly.Poly[T]{Coeffs: ct.Value[1:]}
	e.mulFourierLWEKeyAssign(e.PublicKey.LWEPublicKey.Value[1], e.buffer.auxFourierLWEKey, ctMaskPoly)
	e.GaussianSampler.SampleSliceAddAssign(e.Parameters.DefaultLWEStdDev(), ctMaskPoly.Coeffs)
}

// EncryptLev encrypts integer message to Lev ciphertext.
func (e *PublicEncryptor[T]) EncryptLev(message int, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptLevPlaintext(pt, gadgetParams)
}

// EncryptLevAssign encrypts integer message to Lev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLevAssign(message int, ctOut LevCiphertext[T]) {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	e.EncryptLevPlaintextAssign(pt, ctOut)
}

// EncryptLevPlaintext encrypts LWE plaintext to Lev ciphertext.
func (e *PublicEncryptor[T]) EncryptLevPlaintext(pt LWEPlaintext[T], gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ct := NewLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptLevPlaintextAssign encrypts LWE plaintext to Lev ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLevPlaintextAssign(pt LWEPlaintext[T], ctOut LevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		ctOut.Value[i].Value[0] = pt.Value << ctOut.GadgetParameters.ScaledBaseLog(i)
		e.EncryptLWEBody(ctOut.Value[i])
	}
}
