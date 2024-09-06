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
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEPlaintextAssign(pt, ct)
	return ct
}

// EncryptLWEPlaintextAssign encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLWEPlaintextAssign(pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEBody(ctOut)
}

// EncryptLWEBody encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e *Encryptor[T]) EncryptLWEBody(ct LWECiphertext[T]) {
	e.UniformSampler.SampleSliceAssign(ct.Value[1:])
	ct.Value[0] += -vec.Dot(ct.Value[1:], e.DefaultLWESecretKey().Value)
	ct.Value[0] += e.GaussianSampler.Sample(e.Parameters.DefaultLWEStdDevQ())
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) LWEPlaintext[T] {
	pt := ct.Value[0] + vec.Dot(ct.Value[1:], e.DefaultLWESecretKey().Value)
	return LWEPlaintext[T]{Value: pt}
}

// EncryptLev encrypts integer message to Lev ciphertext.
func (e *Encryptor[T]) EncryptLev(message int, gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptLevPlaintext(pt, gadgetParams)
}

// EncryptLevAssign encrypts integer message to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevAssign(message int, ctOut LevCiphertext[T]) {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	e.EncryptLevPlaintextAssign(pt, ctOut)
}

// EncryptLevPlaintext encrypts LWE plaintext to Lev ciphertext.
func (e *Encryptor[T]) EncryptLevPlaintext(pt LWEPlaintext[T], gadgetParams GadgetParameters[T]) LevCiphertext[T] {
	ct := NewLevCiphertext(e.Parameters, gadgetParams)
	e.EncryptLevPlaintextAssign(pt, ct)
	return ct
}

// EncryptLevPlaintextAssign encrypts LWE plaintext to Lev ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevPlaintextAssign(pt LWEPlaintext[T], ctOut LevCiphertext[T]) {
	for i := 0; i < ctOut.GadgetParameters.level; i++ {
		ctOut.Value[i].Value[0] = pt.Value << ctOut.GadgetParameters.BaseQLog(i)
		e.EncryptLWEBody(ctOut.Value[i])
	}
}

// DecryptLev decrypts Lev ciphertext to integer message.
func (e *Encryptor[T]) DecryptLev(ct LevCiphertext[T]) int {
	pt := e.DecryptLevPlaintext(ct)
	return int(num.DivRoundBits(pt.Value, ct.GadgetParameters.LastBaseQLog()) % e.Parameters.messageModulus)
}

// DecryptLevPlaintext decrypts Lev ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptLevPlaintext(ct LevCiphertext[T]) LWEPlaintext[T] {
	ctLastLevel := ct.Value[ct.GadgetParameters.level-1]
	return e.DecryptLWEPlaintext(ctLastLevel)
}

// EncryptGSW encrypts integer message to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSW(message int, gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptGSWPlaintext(pt, gadgetParams)
}

// EncryptGSWAssign encrypts integer message to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWAssign(message int, ctOut GSWCiphertext[T]) {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	e.EncryptGSWPlaintextAssign(pt, ctOut)
}

// EncryptGSWPlaintext encrypts LWE plaintext to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSWPlaintext(pt LWEPlaintext[T], gadgetParams GadgetParameters[T]) GSWCiphertext[T] {
	ct := NewGSWCiphertext(e.Parameters, gadgetParams)
	e.EncryptGSWPlaintextAssign(pt, ct)
	return ct
}

// EncryptGSWPlaintextAssign encrypts LWE plaintext to GSW ciphertext and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWPlaintextAssign(pt LWEPlaintext[T], ctOut GSWCiphertext[T]) {
	e.EncryptLevPlaintextAssign(pt, ctOut.Value[0])

	for i := 0; i < e.Parameters.DefaultLWEDimension(); i++ {
		for j := 0; j < ctOut.GadgetParameters.level; j++ {
			ctOut.Value[i+1].Value[j].Value[0] = e.DefaultLWESecretKey().Value[i] * pt.Value << ctOut.GadgetParameters.BaseQLog(j)
			e.EncryptLWEBody(ctOut.Value[i+1].Value[j])
		}
	}
}

// DecryptGSW decrypts GSW ciphertext to integer message.
func (e *Encryptor[T]) DecryptGSW(ct GSWCiphertext[T]) int {
	return e.DecryptLev(ct.Value[0])
}

// DecryptGSWPlaintext decrypts GSW ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptGSWPlaintext(ct GSWCiphertext[T]) LWEPlaintext[T] {
	return e.DecryptLevPlaintext(ct.Value[0])
}
