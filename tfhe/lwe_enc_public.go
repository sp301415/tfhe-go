package tfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWETo encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWETo(ctOut LWECiphertext[T], message int) {
	e.EncryptLWEPlaintextTo(ctOut, e.EncodeLWE(message))
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *PublicEncryptor[T]) EncryptLWEPlaintext(pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.EncryptLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptLWEPlaintextTo encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *PublicEncryptor[T]) EncryptLWEPlaintextTo(ctOut LWECiphertext[T], pt LWEPlaintext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *PublicEncryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	for i := 0; i < e.Params.glweRank; i++ {
		e.BinarySampler.SamplePolyTo(e.buf.auxKey.Value[i])
		ct.Value[0] += vec.Dot(e.buf.auxKey.Value[i].Coeffs, e.PublicKey.LWEKey.Value[i].Value[0].Coeffs)
	}
	ct.Value[0] += e.GaussianSampler.Sample(e.Params.GLWEStdDevQ())

	for i := 0; i < e.Params.glweRank; i++ {
		vec.ReverseInPlace(e.buf.auxKey.Value[i].Coeffs)
	}
	e.FwdFFTGLWESecretKeyTo(e.buf.auxFourierKey, e.buf.auxKey)

	ctGLWE := make([]poly.Poly[T], e.Params.glweRank)
	for i := 0; i < e.Params.glweRank; i++ {
		ctGLWE[i] = poly.Poly[T]{Coeffs: ct.Value[1+i*e.Params.polyRank : 1+(i+1)*e.Params.polyRank]}
	}

	for i := 0; i < e.Params.glweRank; i++ {
		for j := 0; j < e.Params.glweRank; j++ {
			e.PolyEvaluator.ShortFFTPolyMulAddPolyTo(ctGLWE[j], e.PublicKey.LWEKey.Value[i].Value[j+1], e.buf.auxFourierKey.Value[i])
		}
	}

	for j := 0; j < e.Params.glweRank; j++ {
		e.GaussianSampler.SamplePolyAddTo(ctGLWE[j], e.Params.GLWEStdDevQ())
	}
}
