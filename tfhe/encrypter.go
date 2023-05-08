package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
	"github.com/sp301415/tfhe/math/vec"
)

// Encrypter encrypts and decrypts values.
// This is meant to be a private struct.
type Encrypter[T Tint] struct {
	Parameters Parameters[T]

	uniformSampler rand.UniformSampler[T]
	binarySampler  rand.BinarySampler[T]
	lweSampler     rand.GaussianSampler[T]
	glweSampler    rand.GaussianSampler[T]

	polyEvaluator poly.Evaluater[T]

	lweKey  LWEKey[T]
	glweKey GLWEKey[T]
	// lweLargeKey is a LWE key derived from GLWE key.
	lweLargeKey LWEKey[T]

	// buffGLWEPtForGGSW is used to store intermediate Plaintext values
	// especially in GGSW computation.
	buffGLWEPtForGGSW poly.Poly[T]
	// buffGLWEPtForGLev is used to store intermediate Plaintext values
	// especially in GLev computation.
	buffGLWEPtForGLev poly.Poly[T]
}

// NewEncrypter returns a initialized Encrypter with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	encrypter := NewEncrypterWithoutKey(params)

	encrypter.lweKey = encrypter.SampleLWEKey()
	encrypter.glweKey = encrypter.SampleGLWEKey()
	encrypter.lweLargeKey = encrypter.glweKey.ToLWEKey()

	return encrypter
}

// NewEncrypterWithoutKey returns a initialized Encrypter, but without key added.
// If you try to encrypt without keys, it will panic.
// You can supply LWE or GLWE key later by using SetLWEKey() or SetGLWEKey().
func NewEncrypterWithoutKey[T Tint](params Parameters[T]) Encrypter[T] {
	return Encrypter[T]{
		Parameters: params,

		uniformSampler: rand.UniformSampler[T]{},
		binarySampler:  rand.BinarySampler[T]{},
		lweSampler:     rand.GaussianSampler[T]{StdDev: params.lweStdDev * float64(num.MaxT[T]())},
		glweSampler:    rand.GaussianSampler[T]{StdDev: params.glweStdDev * float64(num.MaxT[T]())},

		polyEvaluator: poly.NewEvaluater[T](params.polyDegree),

		buffGLWEPtForGGSW: poly.New[T](params.polyDegree),
		buffGLWEPtForGLev: poly.New[T](params.polyDegree),
	}
}

// LWEKey returns a copy of LWE key.
func (e Encrypter[T]) LWEKey() LWEKey[T] {
	return e.lweKey.Copy()
}

// GLWEKey returns a copy of GLWE key.
func (e Encrypter[T]) GLWEKey() GLWEKey[T] {
	return e.glweKey.Copy()
}

// SetLWEKey sets the LWE key to copy of sk.
func (e *Encrypter[T]) SetLWEKey(sk LWEKey[T]) {
	e.lweKey = sk.Copy()
}

// SetGLWEKey sets the GLWE key to copy of sk.
func (e *Encrypter[T]) SetGLWEKey(sk GLWEKey[T]) {
	e.glweKey = sk.Copy()
	e.lweLargeKey = sk.ToLWEKey()
}

// EncodeLWE encodes an integer message to LWE plaintext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog}
}

// EncodeLWEDelta encodes an integer message with custom deltaLog.
// It does not handle message modulus.
func (e Encrypter[T]) EncodeLWEDelta(message int, delta T) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: T(message) * delta}
}

// DecodeLWE deocdes the LWE plaintext into integer message.
func (e Encrypter[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	messageDeltaLog := 63 - (e.Parameters.messageModulusLog + e.Parameters.carryModulusLog)
	closest_representable := num.RoundRatioBits(pt.Value, messageDeltaLog) << messageDeltaLog
	return int(num.RoundRatioBits(closest_representable, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// DecodeLWEDelta decodes an integer message with custom delta.
// It does not handle message modulus.
func (e Encrypter[T]) DecodeLWEDelta(pt LWEPlaintext[T], delta int) int {
	return int(num.RoundRatio(pt.Value, T(delta)))
}

// Encrypt encrypts an integer message to LWE ciphertext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) Encrypt(message int) LWECiphertext[T] {
	return e.EncryptLWE(e.EncodeLWE(message))
}

// EncryptLWE encrypts a LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(pt LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEInPlace(pt, ct)
	return ct
}

// EncryptLWEInPlace encrypts pt and saves it to ct.
func (e Encrypter[T]) EncryptLWEInPlace(pt LWEPlaintext[T], ct LWECiphertext[T]) {
	// ct = (b = <a, s> + pt + e, a_1, ..., a_n)
	e.uniformSampler.SampleSlice(ct.Value[1:])
	ct.Value[0] = vec.Dot(ct.Value[1:], e.lweKey.Value) + pt.Value + e.lweSampler.Sample()
}

// EncryptLevInPlace encrypts a LWE plaintext to leveled LWE ciphertext.
func (e Encrypter[T]) EncryptLevInPlace(pt LWEPlaintext[T], ct LevCiphertext[T]) {
	for i := 0; i < ct.decompParams.level; i++ {
		e.EncryptLWEInPlace(LWEPlaintext[T]{Value: pt.Value << ct.decompParams.ScaledBaseLog(i)}, ct.Value[i])
	}
}

// Decrypt decrypts a LWE ciphertext to integer message.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) Decrypt(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWE(ct))
}

// DecryptLWE decrypts a LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := ct.Value[0] - vec.Dot(ct.Value[1:], e.lweKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// DecryptLevInPlace decrypts leveled LWE ciphertexts to LWE plaintext.
func (e Encrypter[T]) DecryptLev(ct LevCiphertext[T]) LWEPlaintext[T] {
	lweCt := ct.Value[ct.decompParams.level-1]
	pt := e.DecryptLWE(lweCt)
	return LWEPlaintext[T]{Value: num.RoundRatioBits(pt.Value, ct.decompParams.LastScaledBaseLog())}
}

// EncodeGLWE encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
//
// If len(messages) < Parameters.PolyDegree, the leftovers are padded with zero.
// If len(messages) > Parameters.PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i, message := range messages {
		if i >= e.Parameters.polyDegree {
			break
		}
		pt.Value.Coeffs[i] = (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog
	}
	return pt
}

// DecodeGLWE decodes a GLWE plaintext to integer messages.
func (e Encrypter[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messageDeltaLog := 63 - (e.Parameters.messageModulusLog + e.Parameters.carryModulusLog)
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		closest_representable := num.RoundRatioBits(pt.Value.Coeffs[i], messageDeltaLog) << messageDeltaLog
		messages[i] = int((num.RoundRatioBits(closest_representable, e.Parameters.deltaLog) % e.Parameters.messageModulus))
	}
	return messages
}

// EncryptPacked encrypts up to Parameters.PolyDegree integer messages into one GLWE ciphertext.
// However, there are not much to do with GLWE ciphertext, so this is only useful
// when you want to reduce communication costs.
//
// If len(messages) < Parameters.PolyDegree, the leftovers are padded with zero.
// If len(messages) > Parameters.PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncryptPacked(messages []int) GLWECiphertext[T] {
	return e.EncryptGLWE(e.EncodeGLWE(messages))
}

// EncryptGLWE encrypts a GLWE plaintext to GLWE ciphertext.
func (e Encrypter[T]) EncryptGLWE(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEInPlace(pt, ct)
	return ct
}

// EncryptGLWEInPlace encrypts pt and saves it to ct.
func (e Encrypter[T]) EncryptGLWEInPlace(pt GLWEPlaintext[T], ct GLWECiphertext[T]) {
	// ct = (b = sum a*s + pt + e, a_1, ..., a_k)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.uniformSampler.SamplePoly(ct.Value[i+1])
	}

	e.glweSampler.SamplePoly(ct.Value[0])
	e.polyEvaluator.AddAssign(pt.Value, ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.Value[i+1], e.glweKey.Value[i], ct.Value[0])
	}
}

// EncryptGLevInPlace encrypts GLWE plaintext to GLev ciphertexts.
func (e Encrypter[T]) EncryptGLevInPlace(pt GLWEPlaintext[T], ct GLevCiphertext[T]) {
	e.polyEvaluator.ScalarMulInPlace(pt.Value, ct.decompParams.FirstScaledBase(), e.buffGLWEPtForGLev)

	for i := 0; i < ct.decompParams.level; i++ {
		e.EncryptGLWEInPlace(GLWEPlaintext[T]{Value: e.buffGLWEPtForGLev}, ct.Value[i])

		if i < ct.decompParams.level-1 { // Skip last loop
			e.polyEvaluator.ScalarDivAssign(ct.decompParams.base, e.buffGLWEPtForGLev)
		}
	}
}

// DecryptPacked decrypts a GLWE ciphertext to integer messages.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) DecryptPacked(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWE(ct))
}

// DecryptGLWE decrypts a GLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEInPlace(ct, pt)
	return pt
}

// DecryptGLWEInPlace decrypts ct and saves it to pt.
func (e Encrypter[T]) DecryptGLWEInPlace(ct GLWECiphertext[T], pt GLWEPlaintext[T]) {
	// pt = b - sum a*s
	pt.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.Value[i+1], e.glweKey.Value[i], pt.Value)
	}
}

// DecryptGLevInPlace decrypts GLev ciphertexts to GLWE plaintext.
func (e Encrypter[T]) DecryptGLevInPlace(ct GLevCiphertext[T], pt GLWEPlaintext[T]) {
	glweCt := ct.Value[ct.decompParams.level-1] // Pick the last level, encrypting msg * Q / Base^Level
	e.DecryptGLWEInPlace(glweCt, pt)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		pt.Value.Coeffs[i] = num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog())
	}
}

// EncryptGSWInPlace encrypts LWE plaintext to GSW ciphertexts.
func (e Encrypter[T]) EncryptGSWInPlace(pt LWEPlaintext[T], ct GSWCiphertext[T]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		if i == 0 {
			e.EncryptLevInPlace(pt, ct.Value[i])
		} else {
			e.EncryptLevInPlace(LWEPlaintext[T]{Value: -e.lweKey.Value[i-1] * pt.Value}, ct.Value[i])
		}
	}
}

// DecryptGSW decrypts a GSW ciphertext to messages.
func (e Encrypter[T]) DecryptGSW(ct GSWCiphertext[T]) LWEPlaintext[T] {
	return e.DecryptLev(ct.ToLev())
}

// EncryptGGSW encrypts GLWE plaintext to GGSW ciphertext and returns it.
func (e Encrypter[T]) EncryptGGSW(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ct := NewGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGGSWInPlace(pt, ct)
	return ct
}

// EncryptGGSWInPlace encrypts GLWE plaintext to GGSW ciphertext.
func (e Encrypter[T]) EncryptGGSWInPlace(pt GLWEPlaintext[T], ct GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		if i == 0 {
			e.buffGLWEPtForGGSW.CopyFrom(pt.Value)
		} else {
			e.polyEvaluator.MulInPlace(pt.Value, e.glweKey.Value[i-1], e.buffGLWEPtForGGSW)
			e.polyEvaluator.NegAssign(e.buffGLWEPtForGGSW)
		}
		e.EncryptGLevInPlace(GLWEPlaintext[T]{Value: e.buffGLWEPtForGGSW}, ct.Value[i])
	}
}

// DecryptGGSW decrypts a GGSW ciphertext to GLWE plaintext and returns it.
func (e Encrypter[T]) DecryptGGSW(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevInPlace(ct.ToGLev(), pt)
	return pt
}

// DecryptGGSWInPlace decrypts a GGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGGSWInPlace(ct GGSWCiphertext[T], pt GLWEPlaintext[T]) {
	e.DecryptGLevInPlace(ct.ToGLev(), pt)
}
