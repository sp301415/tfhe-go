package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e *Encryptor[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
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
	e.uniformSampler.SampleSliceAssign(ct.Value[1:])
	ct.Value[0] += vec.Dot(ct.Value[1:], e.SecretKey.LWEKey.Value) + e.lweSampler.Sample()
	vec.NegAssign(ct.Value[1:], ct.Value[1:])
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (e *Encryptor[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) LWEPlaintext[T] {
	pt := ct.Value[0] + vec.Dot(ct.Value[1:], e.SecretKey.LWEKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// EncryptLev encrypts integer message to Lev ciphertext.
func (e *Encryptor[T]) EncryptLev(message int, decompParams DecompositionParameters[T]) LevCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptLevPlaintext(pt, decompParams)
}

// EncryptLevPlaintext encrypts LWE plaintext to Lev ciphertext.
func (e *Encryptor[T]) EncryptLevPlaintext(pt LWEPlaintext[T], decompParams DecompositionParameters[T]) LevCiphertext[T] {
	ctOut := NewLevCiphertext(e.Parameters, decompParams)
	e.EncryptLevPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptLevPlaintextAssign encrypts LWE plaintext to Lev ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) EncryptLevPlaintextAssign(pt LWEPlaintext[T], ctOut LevCiphertext[T]) {
	for i := 0; i < ctOut.decompParams.level; i++ {
		ctOut.Value[i].Value[0] = pt.Value << ctOut.decompParams.ScaledBaseLog(i)
		e.EncryptLWEBody(ctOut.Value[i])
	}
}

// DecryptLev decrypts Lev ciphertext to integer message.
func (e *Encryptor[T]) DecryptLev(ct LevCiphertext[T]) int {
	pt := e.DecryptLevPlaintext(ct)
	return int(num.RoundRatioBits(pt.Value, ct.decompParams.LastScaledBaseLog()) % e.Parameters.messageModulus)
}

// DecryptLevPlaintext decrypts Lev ciphertext to LWE plaintext.
func (e *Encryptor[T]) DecryptLevPlaintext(ct LevCiphertext[T]) LWEPlaintext[T] {
	ctLastLevel := ct.Value[ct.decompParams.level-1]
	return e.DecryptLWEPlaintext(ctLastLevel)
}

// EncryptGSW encrypts integer message to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSW(message int, decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptGSWPlaintext(pt, decompParams)
}

// EncryptGSWPlaintext encrypts LWE plaintext to GSW ciphertext.
func (e *Encryptor[T]) EncryptGSWPlaintext(pt LWEPlaintext[T], decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	ctOut := NewGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGSWPlaintextAssign(pt, ctOut)
	return ctOut
}

// EncryptGSWPlaintextAssign encrypts LWE plaintext to GSW ciphertext, and writes it to ctOut.
func (e *Encryptor[T]) EncryptGSWPlaintextAssign(pt LWEPlaintext[T], ctOut GSWCiphertext[T]) {
	e.EncryptLevPlaintextAssign(pt, ctOut.Value[0])

	for i := 1; i < e.Parameters.lweDimension+1; i++ {
		for j := 0; j < ctOut.decompParams.level; j++ {
			ctOut.Value[i].Value[j].Value[0] = e.SecretKey.LWEKey.Value[i-1] * pt.Value << ctOut.decompParams.ScaledBaseLog(j)
			e.EncryptLWEBody(ctOut.Value[i].Value[j])
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
