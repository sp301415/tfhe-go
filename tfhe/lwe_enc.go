package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWETo encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWETo(ctOut LWECiphertext[T], message int) {
	e.EncryptLWEPlaintextTo(ctOut, e.EncodeLWE(message))
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWEPlaintext(pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Params)
	e.EncryptLWEPlaintextTo(ctOut, pt)
	return ctOut
}

// EncryptLWEPlaintextTo encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEPlaintextTo(ctOut LWECiphertext[T], pt LWEPlaintext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.UniformSampler.SampleVecTo(ct.Value[1:])
	ct.Value[0] += -vec.Dot(ct.Value[1:], e.DefaultLWESecretKey().Value)
	ct.Value[0] += e.GaussianSampler.Sample(e.Params.DefaultLWEStdDevQ())
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWEPhase(ct))
}

// DecryptLWEPhase decrypts LWE ciphertext to LWE plaintext including errors.
func (e *Encryptor[T]) DecryptLWEPhase(ct LWECiphertext[T]) LWEPlaintext[T] {
	ptOut := ct.Value[0] + vec.Dot(ct.Value[1:], e.DefaultLWESecretKey().Value)
	return LWEPlaintext[T]{Value: ptOut}
}

// EncryptLev encrypts integer message to Lev ciphertext.
func (e *Encryptor[T]) EncryptLev(message int, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	return e.EncryptLevScalar(T(message)%e.Params.messageModulus, gadgetParams)
}

// EncryptLevTo encrypts integer message to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevTo(ctOut LevCiphertext[T], message int) {
	e.EncryptLevScalarTo(ctOut, T(message)%e.Params.messageModulus)
}

// EncryptLevScalar encrypts scalar to Lev ciphertext.
func (e *Encryptor[T]) EncryptLevScalar(c T, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ctOut := NewLevCiphertext(e.Params, gadgetParams)
	e.EncryptLevScalarTo(ctOut, c)
	return ctOut
}

// EncryptLevScalarTo encrypts scalar to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevScalarTo(ctOut LevCiphertext[T], c T) {
	for i := 0; i < ctOut.GadgetParams.level; i++ {
		ctOut.Value[i].Value[0] = c << ctOut.GadgetParams.LogBaseQ(i)
		e.EncryptLWEBody(ctOut.Value[i])
	}
}

// DecryptLev decrypts Lev ciphertext to integer message.
func (e *Encryptor[T]) DecryptLev(ct LevCiphertext[T]) int {
	return int(e.DecryptLevScalar(ct) % e.Params.messageModulus)
}

// DecryptLevScalar decrypts Lev ciphertext to scalar.
func (e *Encryptor[T]) DecryptLevScalar(ct LevCiphertext[T]) T {
	ptOut := e.DecryptLWEPhase(ct.Value[0])
	return num.DivRoundBits(ptOut.Value, ct.GadgetParams.LogFirstBaseQ()) % ct.GadgetParams.base
}

// EncryptGSW encrypts integer message to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSW(message int, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	return e.EncryptGSWScalar(T(message)%e.Params.messageModulus, gadgetParams)
}

// EncryptGSWTo encrypts integer message to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWTo(ctOut GSWCiphertext[T], message int) {
	e.EncryptGSWScalarTo(ctOut, T(message)%e.Params.messageModulus)
}

// EncryptGSWScalar encrypts scalar to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSWScalar(c T, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	ctOut := NewGSWCiphertext(e.Params, gadgetParams)
	e.EncryptGSWScalarTo(ctOut, c)
	return ctOut
}

// EncryptGSWScalarTo encrypts LWE plaintext to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWScalarTo(ctOut GSWCiphertext[T], c T) {
	e.EncryptLevScalarTo(ctOut.Value[0], c)

	for i := 0; i < e.Params.DefaultLWEDimension(); i++ {
		for j := 0; j < ctOut.GadgetParams.level; j++ {
			ctOut.Value[i+1].Value[j].Value[0] = e.DefaultLWESecretKey().Value[i] * c << ctOut.GadgetParams.LogBaseQ(j)
			e.EncryptLWEBody(ctOut.Value[i+1].Value[j])
		}
	}
}

// DecryptGSW decrypts GSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptGSW(ct GSWCiphertext[T]) int {
	return e.DecryptLev(ct.Value[0])
}

// DecryptGSWScalar decrypts GSW ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptGSWScalar(ct GSWCiphertext[T]) T {
	return e.DecryptLevScalar(ct.Value[0])
}
