package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

// EncodeLWE encodes integer message to LWE plaintext.
// Parameter's MessageModulus and Delta are used.
func (e Encrypter[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog}
}

// EncodeLWECustom encodes integer message to LWE plaintext
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e Encrypter[T]) EncodeLWECustom(message int, messageModulus, delta T) LWEPlaintext[T] {
	encoded := T(message)
	if messageModulus != 0 {
		encoded %= messageModulus
	}
	return LWEPlaintext[T]{Value: encoded * delta}
}

// DecodeLWE decodes LWE plaintext to integer message.
// Parameter's MessageModulus and Delta are used.
func (e Encrypter[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatioBits(pt.Value, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// DecodeLWECustom decodes LWE plaintext to integer message
// using custom MessageModulus and Delta.
//
// If MessageModulus = 0, then no modulus reduction is performed.
func (e Encrypter[T]) DecodeLWECustom(pt LWEPlaintext[T], messageModulus, delta T) int {
	decoded := num.RoundRatio(pt.Value, delta)
	if messageModulus != 0 {
		decoded %= messageModulus
	}
	return int(decoded)
}

// EncryptLWE encodes and encrypts integer message to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(message int) LWECiphertext[T] {
	return e.EncryptLWEPlaintext(e.EncodeLWE(message))
}

// EncryptLWEPlaintext encrypts LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWEPlaintext(pt LWEPlaintext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.EncryptLWEInPlace(pt, ctOut)
	return ctOut
}

// EncryptLWEInPlace encrypts LWE plaintext to LWE ciphertext and writes it to ctOut.
func (e Encrypter[T]) EncryptLWEInPlace(pt LWEPlaintext[T], ctOut LWECiphertext[T]) {
	ctOut.Value[0] = pt.Value
	e.EncryptLWEAssign(ctOut)
}

// EncryptLWEAssign encrypts the value in the body of LWE ciphertext and overrides it.
// This avoids the need for most buffers.
func (e Encrypter[T]) EncryptLWEAssign(ct LWECiphertext[T]) {
	e.uniformSampler.SampleSliceAssign(ct.Value[1:])
	ct.Value[0] += vec.Dot(ct.Value[1:], e.SecretKey.LWEKey.Value) + e.lweSampler.Sample()
}

// DecryptLWE decrypts and decodes LWE ciphertext to integer message.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWEPlaintext(ct))
}

// DecryptLWEPlaintext decrypts LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWEPlaintext(ct LWECiphertext[T]) LWEPlaintext[T] {
	pt := ct.Value[0] - vec.Dot(ct.Value[1:], e.SecretKey.LWEKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// EncryptLev encrypts integer message to Lev ciphertext.
func (e Encrypter[T]) EncryptLev(message int, decompParams DecompositionParameters[T]) LevCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptLevPlaintext(pt, decompParams)
}

// EncryptLevPlaintext encrypts LWE plaintext to Lev ciphertext.
func (e Encrypter[T]) EncryptLevPlaintext(pt LWEPlaintext[T], decompParams DecompositionParameters[T]) LevCiphertext[T] {
	ctOut := NewLevCiphertext(e.Parameters, decompParams)
	e.EncryptLevInPlace(pt, ctOut)
	return ctOut
}

// EncryptLevInPlace encrypts LWE plaintext to Lev ciphertext, and writes it to ctOut.
func (e Encrypter[T]) EncryptLevInPlace(pt LWEPlaintext[T], ctOut LevCiphertext[T]) {
	for i := 0; i < ctOut.decompParams.level; i++ {
		ctOut.Value[i].Value[0] = pt.Value << ctOut.decompParams.ScaledBaseLog(i)
		e.EncryptLWEAssign(ctOut.Value[i])
	}
}

// DecryptLev decrypts Lev ciphertext to integer message.
func (e Encrypter[T]) DecryptLev(ct LevCiphertext[T]) int {
	pt := e.DecryptLevPlaintext(ct)
	return int(num.RoundRatioBits(pt.Value, ct.decompParams.LastScaledBaseLog()) % e.Parameters.messageModulus)
}

// DecryptLevPlaintext decrypts Lev ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLevPlaintext(ct LevCiphertext[T]) LWEPlaintext[T] {
	ctLastLevel := ct.Value[ct.decompParams.level-1]
	return e.DecryptLWEPlaintext(ctLastLevel)
}

// EncryptGSW encrypts integer message to GSW ciphertext.
func (e Encrypter[T]) EncryptGSW(message int, decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptGSWPlaintext(pt, decompParams)
}

// EncryptGSWPlaintext encrypts LWE plaintext to GSW ciphertext.
func (e Encrypter[T]) EncryptGSWPlaintext(pt LWEPlaintext[T], decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	ctOut := NewGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGSWInPlace(pt, ctOut)
	return ctOut
}

// EncryptGSWInPlace encrypts LWE plaintext to GSW ciphertext, and writes it to ctOut.
func (e Encrypter[T]) EncryptGSWInPlace(pt LWEPlaintext[T], ctOut GSWCiphertext[T]) {
	e.EncryptLevInPlace(pt, ctOut.Value[0])

	for i := 1; i < e.Parameters.lweDimension+1; i++ {
		for j := 0; j < ctOut.decompParams.level; j++ {
			ctOut.Value[i].Value[j].Value[0] = -e.SecretKey.LWEKey.Value[i-1] * pt.Value << ctOut.decompParams.ScaledBaseLog(j)
			e.EncryptLWEAssign(ctOut.Value[i].Value[j])
		}
	}
}

// DecryptGSW decrypts GSW ciphertext to integer message.
func (e Encrypter[T]) DecryptGSW(ct GSWCiphertext[T]) int {
	return e.DecryptLev(ct.Value[0])
}

// DecryptGSWPlaintext decrypts GSW ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptGSWPlaintext(ct GSWCiphertext[T]) LWEPlaintext[T] {
	return e.DecryptLevPlaintext(ct.Value[0])
}
