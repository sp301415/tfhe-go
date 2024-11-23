package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEAssign encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
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
	for i := 0; i < e.Parameters.glweRank; i++ {
		e.BinarySampler.SamplePolyAssign(e.buffer.auxKey.Value[i])
		ct.Value[0] += vec.Dot(e.buffer.auxKey.Value[i].Coeffs, e.PublicKey.LWEKey.Value[i].Value[0].Coeffs)
	}
	ct.Value[0] += e.GaussianSampler.Sample(e.Parameters.GLWEStdDevQ())

	for i := 0; i < e.Parameters.glweRank; i++ {
		vec.ReverseInPlace(e.buffer.auxKey.Value[i].Coeffs)
	}
	e.ToFourierGLWESecretKeyAssign(e.buffer.auxKey, e.buffer.auxFourierKey)

	ctGLWE := make([]poly.Poly[T], e.Parameters.glweRank)
	for i := 0; i < e.Parameters.glweRank; i++ {
		ctGLWE[i] = poly.Poly[T]{Coeffs: ct.Value[1+i*e.Parameters.polyDegree : 1+(i+1)*e.Parameters.polyDegree]}
	}

	for i := 0; i < e.Parameters.glweRank; i++ {
		for j := 0; j < e.Parameters.glweRank; j++ {
			e.PolyEvaluator.ShortFourierPolyMulAddPolyAssign(e.PublicKey.LWEKey.Value[i].Value[j+1], e.buffer.auxFourierKey.Value[i], ctGLWE[j])
		}
	}

	for j := 0; j < e.Parameters.glweRank; j++ {
		e.GaussianSampler.SamplePolyAddAssign(e.Parameters.GLWEStdDevQ(), ctGLWE[j])
	}
}
