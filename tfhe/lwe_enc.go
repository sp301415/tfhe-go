package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEAssign encodes and encrypts integer message to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEAssign(message int, ctOut LWECiphertext[T]) {
	e.EncryptLWEPlaintextAssign(e.EncodeLWE(message), ctOut)
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWEPlaintext(pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.EncryptLWEPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptLWEPlaintextAssign encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEPlaintextAssign(pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.UniformSampler.SampleVecAssign(ct.Value[1:])
	ct.Value[0] += -vec.Dot(ct.Value[1:], e.DefaultLWESecretKey().Value)
	ct.Value[0] += e.GaussianSampler.Sample(e.Parameters.DefaultLWEStdDevQ())
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
	return e.EncryptLevScalar(T(message)%e.Parameters.messageModulus, gadgetParams)
}

// EncryptLevAssign encrypts integer message to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevAssign(message int, ctOut LevCiphertext[T]) {
	e.EncryptLevScalarAssign(T(message)%e.Parameters.messageModulus, ctOut)
}

// EncryptLevScalar encrypts scalar to Lev ciphertext.
func (e *Encryptor[T]) EncryptLevScalar(c T, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ctOut := NewLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptLevScalarAssign(c, ctOut)
	return ctOut
}

// EncryptLevScalarAssign encrypts scalar to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevScalarAssign(c T, ctOut LevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		ctOut.Value[i].Value[0] = c << ctOut.GadgetParameters.LogBaseQ(i)
		e.EncryptLWEBody(ctOut.Value[i])
	}
}

// DecryptLev decrypts Lev ciphertext to integer message.
func (e *Encryptor[T]) DecryptLev(ct LevCiphertext[T]) int {
	return int(e.DecryptLevScalar(ct) % e.Parameters.messageModulus)
}

// DecryptLevScalar decrypts Lev ciphertext to scalar.
func (e *Encryptor[T]) DecryptLevScalar(ct LevCiphertext[T]) T {
	ptOut := e.DecryptLWEPhase(ct.Value[0])
	return num.DivRoundBits(ptOut.Value, ct.GadgetParameters.LogFirstBaseQ()) % ct.GadgetParameters.base
}

// EncryptGSW encrypts integer message to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSW(message int, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	return e.EncryptGSWScalar(T(message)%e.Parameters.messageModulus, gadgetParams)
}

// EncryptGSWAssign encrypts integer message to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWAssign(message int, ctOut GSWCiphertext[T]) {
	e.EncryptGSWScalarAssign(T(message)%e.Parameters.messageModulus, ctOut)
}

// EncryptGSWScalar encrypts scalar to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSWScalar(c T, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	ctOut := NewGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptGSWScalarAssign(c, ctOut)
	return ctOut
}

// EncryptGSWScalarAssign encrypts LWE plaintext to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWScalarAssign(c T, ctOut GSWCiphertext[T]) {
	e.EncryptLevScalarAssign(c, ctOut.Value[0])

	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			ctOut.Value[i+1].Value[j].Value[0] = e.DefaultLWESecretKey().Value[i] * c << ctOut.GadgetParameters.LogBaseQ(j)
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
