package tfhe

import (
	"errors"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
	"github.com/sp301415/tfhe/math/vec"
)

var (
	// ErrTooManyMessages is returned when the message cannot be packed into one GLWE plaintext because len(messages) > Parameters.PolyDegree.
	ErrTooManyMessages = errors.New("too many messages to pack")
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

	lweKey  LWESecretKey[T]
	glweKey GLWESecretKey[T]
}

// NewEncrypter returns the initialized encrypter with given parameters.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	uniformSampler := rand.UniformSampler[T]{}
	binarySampler := rand.BinarySampler[T]{}
	lweSampler := rand.GaussianSampler[T]{StdDev: params.lweStdDev * float64(num.MaxT[T]())}
	glweSampler := rand.GaussianSampler[T]{StdDev: params.glweStdDev * float64(num.MaxT[T]())}

	// Sample binary LWE key
	lweKey := LWESecretKey[T]{Value: binarySampler.SampleSlice(params.lweDimension)}

	// Sample binary GLWE key
	glweKeyBody := make([]poly.Poly[T], params.glweDimension)
	for i := 0; i < params.glweDimension; i++ {
		glweKeyBody[i] = binarySampler.SamplePoly(params.polyDegree)
	}
	glweKey := GLWESecretKey[T]{Value: glweKeyBody}

	return Encrypter[T]{
		Parameters: params,

		uniformSampler: uniformSampler,
		binarySampler:  binarySampler,
		lweSampler:     lweSampler,
		glweSampler:    glweSampler,

		polyEvaluator: poly.NewEvaluater[T](params.polyDegree),

		lweKey:  lweKey,
		glweKey: glweKey,
	}
}

// LWESecretKey returns a copy of LWE secret key.
func (e Encrypter[T]) LWESecretKey() LWESecretKey[T] {
	return e.lweKey.Copy()
}

// GLWESecretKey returns a copy of GLWE secret key.
func (e Encrypter[T]) GLWESecretKey() GLWESecretKey[T] {
	return e.glweKey.Copy()
}

// EncodeLWE encodes an integer message to LWE plaintext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) EncodeLWE(message int) LWEPlaintext[T] {
	return LWEPlaintext[T]{Value: (T(message) % e.Parameters.messageModulus) * e.Parameters.delta}
}

// DecodeLWE deocdes the LWE plaintext into integer message.
func (e Encrypter[T]) DecodeLWE(pt LWEPlaintext[T]) int {
	return int(num.RoundRatio(pt.Value, e.Parameters.delta) % e.Parameters.messageModulus)
}

// Encrypt encrypts an integer message to LWE ciphertext.
// Message will get wrapped around Parameters.MessageModulus.
func (e Encrypter[T]) Encrypt(message int) LWECiphertext[T] {
	return e.EncryptLWE(e.EncodeLWE(message))
}

// EncryptLWE encrypts a LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(pt LWEPlaintext[T]) LWECiphertext[T] {
	// ct = (a_1, ..., a_n, b = <a, s> + pt + e)
	ct := LWECiphertext[T]{Mask: e.uniformSampler.SampleSlice(e.Parameters.lweDimension)}
	ct.Body = vec.Dot(ct.Mask, e.lweKey.Value) + pt.Value + e.lweSampler.Sample()

	return ct
}

// Decrypt decrypts a LWE ciphertext to integer message.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) Decrypt(ct LWECiphertext[T]) int {
	return e.DecodeLWE(e.DecryptLWE(ct))
}

// DecryptLWE decrypts a LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := ct.Body - vec.Dot(ct.Mask, e.lweKey.Value)
	return LWEPlaintext[T]{Value: pt}
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
		pt.Value.Coeffs[i] = (T(message) % e.Parameters.messageModulus) * e.Parameters.delta
	}
	return pt
}

// DecodeGLWE decodes a GLWE plaintext to integer messages.
func (e Encrypter[T]) DecodeGLWE(pt GLWEPlaintext[T]) []int {
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatio(pt.Value.Coeffs[i], e.Parameters.delta) % e.Parameters.messageModulus)
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
	// ct = (a_1, ..., a_k, b = sum a*s + pt + e)
	ct := GLWECiphertext[T]{Mask: make([]poly.Poly[T], e.Parameters.glweDimension), Body: poly.New[T](e.Parameters.polyDegree)}
	for i := 0; i < e.Parameters.glweDimension; i++ {
		ct.Mask[i] = e.uniformSampler.SamplePoly(e.Parameters.polyDegree)
	}

	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.Mask[i], e.glweKey.Value[i], ct.Body)
	}
	e.polyEvaluator.AddAssign(pt.Value, ct.Body)
	e.polyEvaluator.AddAssign(e.glweSampler.SamplePoly(e.Parameters.polyDegree), ct.Body)

	return ct
}

// DecryptPacked decrypts a GLWE ciphertext to integer messages.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) DecryptPacked(ct GLWECiphertext[T]) []int {
	return e.DecodeGLWE(e.DecryptGLWE(ct))
}

// DecryptGLWE decrypts a GLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := GLWEPlaintext[T]{Value: ct.Body.Copy()}
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.Mask[i], e.glweKey.Value[i], pt.Value)
	}
	return pt
}

// EncryptGGSW encrypts up to Parameters.PolyDegree integer message to GGSW ciphertexts, according to decompParams.
//
// If len(messages) < Parameters.PolyDegree, the leftovers are padded with zero.
// If len(messages) > Parameters.PolyDegree, the leftovers are discarded.
//
// Panics if decompParams is invalid.
func (e Encrypter[T]) EncryptGGSW(messages []int, decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	if err := decompParams.IsValid(); err != nil {
		panic(err)
	}

	// Encode messages without padding
	pt := poly.New[T](e.Parameters.polyDegree)
	for i, message := range messages {
		if i >= e.Parameters.polyDegree {
			break
		}
		pt.Coeffs[i] = T(message) % e.Parameters.messageModulus
	}
	buffPt := pt.Copy()

	// ct = L + m*G,
	// where L is GLWE Encryption of zero.
	zeroCt := e.EncryptGLWE(NewGLWEPlaintext(e.Parameters))

	ct := NewGGSWCiphertext(e.Parameters, decompParams)
	maxBits := num.TLen[T]()
	for i := 0; i < e.Parameters.glweDimension+1; i++ {
		for j := 0; j < decompParams.Level; j++ {
			// Add zeroCt
			for k := 0; k < e.Parameters.glweDimension; k++ {
				ct.Value[i][j].Mask[k].CopyFrom(zeroCt.Body)
			}
			ct.Value[i][j].Body.CopyFrom(zeroCt.Body)

			// Add m*G
			factor := T(1 << (maxBits - (j+1)*decompParams.BaseLog()))
			e.polyEvaluator.ScalarMulInPlace(pt, factor, buffPt)
			if i < e.Parameters.glweDimension {
				e.polyEvaluator.AddAssign(buffPt, ct.Value[i][j].Mask[i])
			} else {
				e.polyEvaluator.AddAssign(buffPt, ct.Value[i][j].Body)
			}
		}
	}
	return ct
}

// DecryptGGSW decrypts a GGSW ciphertext to integer messages.
func (e Encrypter[T]) DecryptGGSW(ct GGSWCiphertext[T]) []int {
	// We take the last element of ct
	glweCt := ct.Value[ct.Len()-1][ct.Level()-1]
	pt := e.DecryptGLWE(glweCt)

	maxBits := num.TLen[T]()
	factor := T(1 << (maxBits - ct.decompParams.Level*ct.decompParams.BaseLog()))
	messages := make([]int, e.Parameters.polyDegree)
	for i := 0; i < e.Parameters.polyDegree; i++ {
		messages[i] = int(num.RoundRatio(pt.Value.Coeffs[i], factor))
	}
	return messages
}
