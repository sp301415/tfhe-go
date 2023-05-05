package tfhe

import (
	"errors"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"github.com/sp301415/tfhe/math/rand"
	"github.com/sp301415/tfhe/math/vec"
)

var (
	// ErrMessageOutOfBound is returned when the encrypting message is too large for the given parameters.
	ErrMessageOutOfBound = errors.New("message out of bound")
	// ErrTooManyMessages is returned when the message cannot be packed into one GLWE plaintext because len(messages) > params.PolyDegree.
	ErrTooManyMessages = errors.New("too many messages to pack")
)

// Encrypter encrypts and decrypts values.
// This is meant to be a private struct.
type Encrypter[T Tint] struct {
	params Parameters[T]

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
	lweSampler := rand.GaussianSampler[T]{StdDev: params.lweStdDev}
	glweSampler := rand.GaussianSampler[T]{StdDev: params.glweStdDev}

	// Sample binary LWE key
	lweKey := LWESecretKey[T]{body: binarySampler.SampleSlice(params.lweDimension)}

	// Sample binary GLWE key
	glweKeyBody := make([]poly.Poly[T], params.glweDimension)
	for i := 0; i < params.glweDimension; i++ {
		glweKeyBody[i] = binarySampler.SamplePoly(params.polyDegree)
	}
	glweKey := GLWESecretKey[T]{body: glweKeyBody}

	return Encrypter[T]{
		params: params,

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

// Encrypt encrypts the integer message to LWE ciphertext.
// The bound of the encryptable message is determined by the paramter's MessageModulus.
// If message < 0 or message >= MessageModulus, ErrMessageOutOfBound error is returned.
func (e Encrypter[T]) Encrypt(message int) (LWECiphertext[T], error) {
	if message < 0 || uint64(message) > uint64(e.params.messageModulus) {
		return LWECiphertext[T]{}, ErrMessageOutOfBound
	}

	pt := LWEPlaintext[T]{value: T(message) * e.params.delta}
	return e.EncryptLWE(pt), nil
}

// MustEncrypt is equivalant to Encrypt, but it panics instead of returning error.
func (e Encrypter[T]) MustEncrypt(message int) LWECiphertext[T] {
	ct, err := e.Encrypt(message)
	if err != nil {
		panic(err)
	}
	return ct
}

// EncryptLWE encrypts a LWE plaintext to LWE ciphertext.
func (e Encrypter[T]) EncryptLWE(pt LWEPlaintext[T]) LWECiphertext[T] {
	// ct = (a_1, ..., a_n, b = <a, s> + pt + e)
	ct := LWECiphertext[T]{body: e.uniformSampler.SampleSlice(e.params.lweDimension)}
	ct.mask = vec.Dot(ct.body, e.lweKey.body) + pt.value + e.lweSampler.Sample()

	return ct
}

// Decrypt decrypts a LWE ciphertext to integer message.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) Decrypt(ct LWECiphertext[T]) int {
	pt := e.DecryptLWE(ct)
	message := int(num.RoundRatio(pt.value, e.params.delta))
	return message
}

// DecryptLWE decrypts a LWE ciphertext to LWE plaintext.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) LWEPlaintext[T] {
	// pt = b - <a, s>
	pt := ct.mask - vec.Dot(ct.body, e.lweKey.body)
	return LWEPlaintext[T]{value: pt}
}

// EncryptPacked encrypts up to params.PolyDegree integer messages into one GLWE ciphertext.
// However, there are not much to do with GLWE ciphertext, so this is only useful
// when you want to reduce communication costs.
//
// If message < 0 or message >= MessageModulus, ErrMessageOutOfBound error is returned.
// If len(messages) > params.PolyDegree, ErrTooManyMessages error is returned.
func (e Encrypter[T]) EncryptPacked(messages []int) (GLWECiphertext[T], error) {
	if len(messages) > e.params.polyDegree {
		return GLWECiphertext[T]{}, ErrTooManyMessages
	}

	pt := NewGLWEPlaintext(e.params)
	for i, message := range messages {
		if message < 0 || uint64(message) > uint64(e.params.messageModulus) {
			return GLWECiphertext[T]{}, ErrMessageOutOfBound
		}
		pt.value.Coeffs[i] = T(message) * e.params.delta
	}

	return e.EncryptGLWE(pt), nil
}

// MustEncryptPacked is equivalant to EncryptPacked, but it panics instead of returning error.
func (e Encrypter[T]) MustEncryptPacked(messages []int) GLWECiphertext[T] {
	ct, err := e.EncryptPacked(messages)
	if err != nil {
		panic(err)
	}
	return ct
}

// EncryptGLWE encrypts a GLWE plaintext to GLWE ciphertext.
func (e Encrypter[T]) EncryptGLWE(pt GLWEPlaintext[T]) GLWECiphertext[T] {
	// ct = (a_1, ..., a_k, b = sum a*s + pt + e)
	ct := GLWECiphertext[T]{body: make([]poly.Poly[T], e.params.glweDimension), mask: poly.New[T](e.params.polyDegree)}
	for i := 0; i < e.params.glweDimension; i++ {
		ct.body[i] = e.uniformSampler.SamplePoly(e.params.polyDegree)
	}

	for i := 0; i < e.params.glweDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.body[i], e.glweKey.body[i], ct.mask)
	}
	e.polyEvaluator.AddAssign(pt.value, ct.mask)
	e.polyEvaluator.AddAssign(e.glweSampler.SamplePoly(e.params.polyDegree), ct.mask)

	return ct
}

// DecryptPacked decrypts a GLWE ciphertext to integer messages.
// Decrypt always succeeds, even though the decrypted value could be wrong.
func (e Encrypter[T]) DecryptPacked(ct GLWECiphertext[T]) []int {
	pt := e.DecryptGLWE(ct)

	messages := make([]int, e.params.polyDegree)
	for i := 0; i < e.params.polyDegree; i++ {
		messages[i] = int(num.RoundRatio(pt.value.Coeffs[i], e.params.delta))
	}
	return messages
}

// DecryptGLWE decrypts a GLWE ciphertext to GLWE plaintext.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) GLWEPlaintext[T] {
	pt := GLWEPlaintext[T]{value: ct.mask.Copy()}
	for i := 0; i < e.params.glweDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.body[i], e.glweKey.body[i], pt.value)
	}
	return pt
}
