package tfhe

import (
	"github.com/sp301415/tfhe/math/csprng"
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/vec"
)

// Encrypter encrypts and decrypts TFHE plaintexts and ciphertexts.
// This is meant to be a private-side structure.
//
// Evaluater uses fftw as backend, so manually freeing memory is needed.
// Use defer clause after initialization:
//
//	enc := tfhe.NewEncrypter(params)
//	defer enc.Free()
type Encrypter[T Tint] struct {
	Parameters Parameters[T]

	uniformSampler csprng.UniformSampler[T]
	binarySampler  csprng.BinarySampler[T]
	lweSampler     csprng.GaussianSampler[T]
	glweSampler    csprng.GaussianSampler[T]

	PolyEvaluater      poly.Evaluater[T]
	FourierTransformer poly.FourierTransformer[T]

	lweKey  LWEKey[T]
	glweKey GLWEKey[T]
	// lweLargeKey is a LWE key derived from GLWE key.
	lweLargeKey LWEKey[T]

	buffer encryptionBuffer[T]
}

// encryptionBuffer contains buffer values for Encrypter.
type encryptionBuffer[T Tint] struct {
	// glwePtForGGSW holds GLWE plaintexts in GGSW encryption.
	glwePtForGGSW GLWEPlaintext[T]
	// glwePtForGLev holds GLWE plaintexts in GLev encryption.
	glwePtForGLev GLWEPlaintext[T]
	// GLEWPtForPBSKeyGen holds GLWE plaintexts in bootstrapping key generation.
	glwePtForPBSKeyGen GLWEPlaintext[T]
	// glweCtForFourier holds GLWE ciphertext before applying Fourier Transform
	// in EncryptFourier and DecryptFourier.
	glweCtForFourier GLWECiphertext[T]
}

// NewEncrypter returns a initialized Encrypter with given parameters.
// It also automatically samples LWE and GLWE key.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	encrypter := NewEncrypterWithoutKey(params)

	encrypter.lweKey = encrypter.GenLWEKey()
	encrypter.glweKey = encrypter.GenGLWEKey()
	encrypter.lweLargeKey = encrypter.glweKey.ToLWEKey()

	return encrypter
}

// NewEncrypterWithoutKey returns a initialized Encrypter, but without key added.
// If you try to encrypt without keys, it will panic.
// You can supply LWE or GLWE key later by using SetLWEKey() or SetGLWEKey().
func NewEncrypterWithoutKey[T Tint](params Parameters[T]) Encrypter[T] {
	return Encrypter[T]{
		Parameters: params,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](params.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](params.glweStdDev),

		PolyEvaluater:      poly.NewEvaluater[T](params.polyDegree),
		FourierTransformer: poly.NewFourierTransformer[T](params.polyDegree),

		buffer: newEncryptionBuffer(params),
	}
}

// newEncryptionBuffer allocates an empty encryptionBuffer.
func newEncryptionBuffer[T Tint](params Parameters[T]) encryptionBuffer[T] {
	return encryptionBuffer[T]{
		glwePtForGGSW:      NewGLWEPlaintext(params),
		glwePtForGLev:      NewGLWEPlaintext(params),
		glwePtForPBSKeyGen: NewGLWEPlaintext(params),
		glweCtForFourier:   NewGLWECiphertext(params),
	}
}

// ShallowCopy returns a shallow copy of this Encrypter.
// Returned Encrypter is safe for concurrent use.
func (e Encrypter[T]) ShallowCopy() Encrypter[T] {
	return Encrypter[T]{
		Parameters: e.Parameters,

		uniformSampler: csprng.NewUniformSampler[T](),
		binarySampler:  csprng.NewBinarySampler[T](),
		lweSampler:     csprng.NewGaussianSamplerTorus[T](e.Parameters.lweStdDev),
		glweSampler:    csprng.NewGaussianSamplerTorus[T](e.Parameters.glweStdDev),

		lweKey:      e.lweKey,
		glweKey:     e.glweKey,
		lweLargeKey: e.lweLargeKey,

		PolyEvaluater:      e.PolyEvaluater.ShallowCopy(),
		FourierTransformer: e.FourierTransformer.ShallowCopy(),

		buffer: newEncryptionBuffer(e.Parameters),
	}
}

// Free frees internal fftw data.
func (e Encrypter[T]) Free() {
	e.FourierTransformer.Free()
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
// Message will get wrapped around MessageModulus.
func (e Encrypter[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) << e.Parameters.deltaLog}
}

// DecodeLWE deocdes the LWE plaintext into integer message.
func (e Encrypter[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatioBits(pt.Value, e.Parameters.deltaLog) % e.Parameters.messageModulus)
}

// Encrypt encrypts an integer message to LWE ciphertext. This is the "default" form of encryption.
// Message will get wrapped around MessageModulus.
func (e Encrypter[T]) Encrypt(message int) LWECiphertext[T] {
	return e.EncryptLWE(e.EncodeLWE(message))
}

// EncryptLarge encrypts an integer message to LWE ciphertext, but using key derived from GLWE key.
// The output ciphertext will have dimension GLWEDimension * PolyDegree + 1.
func (e Encrypter[T]) EncryptLarge(message int) LWECiphertext[T] {
	return e.EncryptLWELarge(e.EncodeLWE(message))
}

// EncryptLWE encrypts LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(pt LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLWECiphertext(e.Parameters)
	e.EncryptLWEInPlace(pt, ct)
	return ct
}

// EncryptLWELarge encrypts LWE plaintext to LWE ciphertext, but using key derived from GLWE key.
func (e Encrypter[T]) EncryptLWELarge(pt LWEPlaintext[T]) LWECiphertext[T] {
	ct := NewLargeLWECiphertext(e.Parameters)
	e.EncryptLWELargeInPlace(pt, ct)
	return ct
}

// EncryptLWEInPlace encrypts LWE plaintext and writes it to LWE ciphertext ct.
func (e Encrypter[T]) EncryptLWEInPlace(pt LWEPlaintext[T], ct LWECiphertext[T]) {
	// ct = (b = <a, s> + pt + e, a_1, ..., a_n)
	e.uniformSampler.SampleSliceAssign(ct.Value[1:])
	ct.Value[0] = vec.Dot(ct.Value[1:], e.lweKey.Value) + pt.Value + e.lweSampler.Sample()
}

// EncryptLWELargeInPlace encrypts LWE plaintext and writes it to LWE ciphertext ct, but using key derived from GLWE key.
func (e Encrypter[T]) EncryptLWELargeInPlace(pt LWEPlaintext[T], ct LWECiphertext[T]) {
	// ct = (b = <a, s> + pt + e, a_1, ..., a_n)
	e.uniformSampler.SampleSliceAssign(ct.Value[1:])
	ct.Value[0] = vec.Dot(ct.Value[1:], e.lweLargeKey.Value) + pt.Value + e.lweSampler.Sample()
}

// EncryptLevInPlace encrypts LWE plaintext and writes it to Lev ciphertext ct.
func (e Encrypter[T]) EncryptLevInPlace(pt LWEPlaintext[T], ct LevCiphertext[T]) {
	for i := 0; i < ct.decompParams.level; i++ {
		e.EncryptLWEInPlace(LWEPlaintext[T]{Value: pt.Value << ct.decompParams.ScaledBaseLog(i)}, ct.Value[i])
	}
}

// Decrypt decrypts LWE ciphertext to integer message.
// Decryption always succeeds, even though decrypted value could be wrong.
func (e Encrypter[T]) Decrypt(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWE(ct))
}

// DecryptLarge decrypts LWE ciphertext to integer message, but using key derived from GLWE key.
// Decryption always succeeds, even though decrypted value could be wrong.
func (e Encrypter[T]) DecryptLarge(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWELarge(ct))
}

// DecryptLWE decrypts LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := ct.Value[0] - vec.Dot(ct.Value[1:], e.lweKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// DecryptLWELarge decrypts LWE ciphertext to LWE plaintext, but using key derived from GLWE key.
func (e Encrypter[T]) DecryptLWELarge(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := ct.Value[0] - vec.Dot(ct.Value[1:], e.lweLargeKey.Value)
	return LWEPlaintext[T]{Value: pt}
}

// DecryptLevInPlace decrypts Lev ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLev(ct LevCiphertext[T]) LWEPlaintext[T] {
	lweCt := ct.Value[ct.decompParams.level-1]
	pt := e.DecryptLWE(lweCt)
	return LWEPlaintext[T]{Value: num.RoundRatioBits(pt.Value, ct.decompParams.LastScaledBaseLog())}
}

// EncodeGLWE encodes up to Parameters.PolyDegree integer messages into one GLWE plaintext.
//
// If len(messages) < PolyDegree, the leftovers are padded with zero.
// If len(messages) > PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncodeGLWE(messages []int) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = (T(messages[i]) % e.Parameters.messageModulus) << e.Parameters.deltaLog
	}
	return pt
}

// DecodeGLWE decodes a GLWE plaintext to integer messages.
// The returned messages are always of length PolyDegree.
func (e Encrypter[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int((num.RoundRatioBits(pt.Value.Coeffs[i], e.Parameters.deltaLog) % e.Parameters.messageModulus))
	}
	return messages
}

// EncryptPacked encrypts up to Parameters.PolyDegree integer messages into one GLWE ciphertext.
//
// If len(messages) < PolyDegree, the leftovers are padded with zero.
// If len(messages) > PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncryptPacked(messages []int) GLWECiphertext[T] {
	return e.EncryptGLWE(e.EncodeGLWE(messages))
}

// EncryptGLWE encrypts GLWE plaintext to GLWE ciphertext.
func (e Encrypter[T]) EncryptGLWE(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	ct := NewGLWECiphertext(e.Parameters)
	e.EncryptGLWEInPlace(pt, ct)
	return ct
}

// EncryptGLWEInPlace encrypts GLWE plaintext and writes it to GLWE ciphertext ct.
func (e Encrypter[T]) EncryptGLWEInPlace(pt GLWEPlaintext[T], ct GLWECiphertext[T]) {
	// ct = (b = sum a*s + pt + e, a_1, ..., a_k)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.uniformSampler.SamplePolyAssign(ct.Value[i+1])
	}

	e.glweSampler.SamplePolyAssign(ct.Value[0])
	e.PolyEvaluater.AddAssign(pt.Value, ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.PolyEvaluater.MulAddAssign(ct.Value[i+1], e.glweKey.Value[i], ct.Value[0])
	}
}

// EncryptGLevInPlace encrypts GLWE plaintext to GLev ciphertexts.
func (e Encrypter[T]) EncryptGLevInPlace(pt GLWEPlaintext[T], ct GLevCiphertext[T]) {
	for i := 0; i < ct.decompParams.level; i++ {
		e.PolyEvaluater.ScalarMulInPlace(pt.Value, ct.decompParams.ScaledBase(i), e.buffer.glwePtForGLev.Value)
		e.EncryptGLWEInPlace(e.buffer.glwePtForGLev, ct.Value[i])
	}
}

// DecryptPacked decrypts GLWE ciphertext to integer messages.
// Decryption always succeeds, even though decrypted value could be wrong.
func (e Encrypter[T]) DecryptPacked(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWE(ct))
}

// DecryptGLWE decrypts GLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLWEInPlace(ct, pt)
	return pt
}

// DecryptGLWEInPlace decrypts GLWE ciphertext and writes it to GLWE plaintext pt.
func (e Encrypter[T]) DecryptGLWEInPlace(ct GLWECiphertext[T], pt GLWEPlaintext[T]) {
	// pt = b - sum a*s
	pt.Value.CopyFrom(ct.Value[0])
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.PolyEvaluater.MulSubAssign(ct.Value[i+1], e.glweKey.Value[i], pt.Value)
	}
}

// DecryptGLevInPlace decrypts GLev ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLevInPlace(ct GLevCiphertext[T], pt GLWEPlaintext[T]) {
	glweCt := ct.Value[ct.decompParams.level-1] // Pick the last level, encrypting msg * Q / Base^Level
	e.DecryptGLWEInPlace(glweCt, pt)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		pt.Value.Coeffs[i] = num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog())
	}
}

// EncryptForMul encrypts an integer message to GSW ciphertext, which is optimal for multiplication.
// Message will get wrapped around MessageModulus.
func (e Encrypter[T]) EncryptForMul(message int, decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	pt := LWEPlaintext[T]{Value: T(message) % e.Parameters.messageModulus}
	return e.EncryptGSW(pt, decompParams)
}

// EncryptGSW encrypts LWE plaintext to GSW ciphertext.
func (e Encrypter[T]) EncryptGSW(pt LWEPlaintext[T], decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	ct := NewGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGSWInPlace(pt, ct)
	return ct
}

// EncryptGSWInPlace encrypts LWE plaintext and writes it to GSW ciphertext ct.
func (e Encrypter[T]) EncryptGSWInPlace(pt LWEPlaintext[T], ct GSWCiphertext[T]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		if i == 0 {
			e.EncryptLevInPlace(pt, ct.Value[i])
		} else {
			e.EncryptLevInPlace(LWEPlaintext[T]{Value: -e.lweKey.Value[i-1] * pt.Value}, ct.Value[i])
		}
	}
}

// DecryptForMul decrypts GSW ciphertext to integer message.
// Decryption always succeeds, even though decrypted value could be wrong.
func (e Encrypter[T]) DecryptForMul(ct GSWCiphertext[T]) int {
	return int(e.DecryptGSW(ct).Value)
}

// DecryptGSW decrypts a GSW ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptGSW(ct GSWCiphertext[T]) LWEPlaintext[T] {
	return e.DecryptLev(ct.Value[0])
}

// EncryptGGSW encrypts GLWE plaintext to GGSW ciphertext.
func (e Encrypter[T]) EncryptGGSW(pt GLWEPlaintext[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ct := NewGGSWCiphertext(e.Parameters, decompParams)
	e.EncryptGGSWInPlace(pt, ct)
	return ct
}

// EncryptGGSWInPlace encrypts GLWE plaintext to GGSW ciphertext.
func (e Encrypter[T]) EncryptGGSWInPlace(pt GLWEPlaintext[T], ct GGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		if i == 0 {
			e.EncryptGLevInPlace(pt, ct.Value[i])
		} else {
			e.PolyEvaluater.MulInPlace(pt.Value, e.glweKey.Value[i-1], e.buffer.glwePtForGGSW.Value)
			e.PolyEvaluater.NegAssign(e.buffer.glwePtForGGSW.Value)
			e.EncryptGLevInPlace(e.buffer.glwePtForGGSW, ct.Value[i])
		}
	}
}

// DecryptGGSW decrypts a GGSW ciphertext to GLWE plaintext and returns it.
func (e Encrypter[T]) DecryptGGSW(ct GGSWCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptGLevInPlace(ct.Value[0], pt)
	return pt
}

// DecryptGGSWInPlace decrypts a GGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGGSWInPlace(ct GGSWCiphertext[T], pt GLWEPlaintext[T]) {
	e.DecryptGLevInPlace(ct.Value[0], pt)
}

// EncryptFourierGLWEInPlace encrypts GLWE plaintext and writes it to FourierGLWE ciphertext ct.
func (e Encrypter[T]) EncryptFourierGLWEInPlace(pt GLWEPlaintext[T], ct FourierGLWECiphertext[T]) {
	e.EncryptGLWEInPlace(pt, e.buffer.glweCtForFourier)
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledFourierPolyInPlace(e.buffer.glweCtForFourier.Value[i], ct.Value[i])
	}
}

// DecryptFourierGLWEInPlace decrypts FourierGLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGLWEInPlace(ct FourierGLWECiphertext[T], pt GLWEPlaintext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		e.FourierTransformer.ToScaledStandardPolyInPlace(ct.Value[i], e.buffer.glweCtForFourier.Value[i])
	}
	e.DecryptGLWEInPlace(e.buffer.glweCtForFourier, pt)
}

// EncryptFourierGLevInPlace encrypts GLWE plaintext to FourierGLev ciphertext.
func (e Encrypter[T]) EncryptFourierGLevInPlace(pt GLWEPlaintext[T], ct FourierGLevCiphertext[T]) {
	for i := 0; i < ct.decompParams.level; i++ {
		e.PolyEvaluater.ScalarMulInPlace(pt.Value, ct.decompParams.ScaledBase(i), e.buffer.glwePtForGLev.Value)
		e.EncryptFourierGLWEInPlace(e.buffer.glwePtForGLev, ct.Value[i])
	}
}

// DecryptFourierGLevInPlace decrypts FourierGLev ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGLevInPlace(ct FourierGLevCiphertext[T], pt GLWEPlaintext[T]) {
	fGLWECt := ct.Value[ct.decompParams.level-1] // Pick the last level, encrypting msg * Q / Base^Level
	e.DecryptFourierGLWEInPlace(fGLWECt, pt)

	for i := 0; i < e.Parameters.polyDegree; i++ {
		pt.Value.Coeffs[i] = num.RoundRatioBits(pt.Value.Coeffs[i], ct.decompParams.LastScaledBaseLog())
	}
}

// EncryptPackedForMul encrypts integer messages to FourierGLWE ciphertext, optimized for multiplication.
//   - If len(messages) < PolyDegree, the leftovers are padded with zero.
//   - If len(messages) > PolyDegree, the leftovers are discarded.
func (e Encrypter[T]) EncryptPackedForMul(messages []int, decompParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	for i := 0; i < e.Parameters.polyDegree && i < len(messages); i++ {
		pt.Value.Coeffs[i] = T(messages[i]) % e.Parameters.messageModulus
	}
	return e.EncryptFourierGGSW(pt, decompParams)
}

// EncryptFourierGGSW encrypts GLWE plaintext to FourierGGSW ciphertext.
func (e Encrypter[T]) EncryptFourierGGSW(pt GLWEPlaintext[T], decomopParams DecompositionParameters[T]) FourierGGSWCiphertext[T] {
	ct := NewFourierGGSWCiphertext(e.Parameters, decomopParams)
	e.EncryptFourierGGSWInPlace(pt, ct)
	return ct
}

// EncryptFourierGGSWInPlace encrypts GLWE plaintext to FourierGGSW ciphertext.
func (e Encrypter[T]) EncryptFourierGGSWInPlace(pt GLWEPlaintext[T], ct FourierGGSWCiphertext[T]) {
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		if i == 0 {
			e.EncryptFourierGLevInPlace(pt, ct.Value[i])
		} else {
			e.PolyEvaluater.MulInPlace(pt.Value, e.glweKey.Value[i-1], e.buffer.glwePtForGGSW.Value)
			e.PolyEvaluater.NegAssign(e.buffer.glwePtForGGSW.Value)
			e.EncryptFourierGLevInPlace(e.buffer.glwePtForGGSW, ct.Value[i])
		}
	}
}

// DecryptPackedForMul decrypts FourierGGSW ciphertext to integer messages.
// Decryption always succeeds, even though decrypted value could be wrong.
func (e Encrypter[T]) DecryptPackedForMul(ct FourierGGSWCiphertext[T]) []int {
	return vec.Cast[T, int](e.DecryptFourierGGSW(ct).Value.Coeffs)
}

// DecryptFourierGGSW decrypts FourierGGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGGSW(ct FourierGGSWCiphertext[T]) GLWEPlaintext[T] {
	pt := NewGLWEPlaintext(e.Parameters)
	e.DecryptFourierGGSWInPlace(ct, pt)
	return pt
}

// DecryptFourierGGSWInPlace decrypts a FourierGGSW ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptFourierGGSWInPlace(ct FourierGGSWCiphertext[T], pt GLWEPlaintext[T]) {
	e.DecryptFourierGLevInPlace(ct.Value[0], pt)
}
