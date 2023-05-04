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
	params Parameters[T]

	uniformSampler rand.UniformSampler[T]
	lweSampler     rand.GaussianSampler[T]
	glweSampler    rand.GaussianSampler[T]

	polyEvaluator poly.Evaluater[T]

	lweKey  LWESecretKey[T]
	glweKey GLWESecretKey[T]
}

// NewEncrypter returns the initialized encrypter with given parameters.
func NewEncrypter[T Tint](params Parameters[T]) Encrypter[T] {
	uniformSampler := rand.UniformSampler[T]{}
	lweSampler := rand.GaussianSampler[T]{StdDev: params.LWEStdDev}
	glweSampler := rand.GaussianSampler[T]{StdDev: params.GLWEStdDev}

	// Sample binary LWE key
	lweKey := LWESecretKey[T]{
		body: uniformSampler.SampleBinarySlice(params.LWEDimension),
	}

	// Sample binary GLWE key
	glweKeyBody := make([]poly.Poly[T], params.GLWEDimension)
	for i := 0; i < params.GLWEDimension; i++ {
		glweKeyBody[i] = poly.Poly[T]{Coeffs: uniformSampler.SampleBinarySlice(params.PolyDegree)}
	}
	glweKey := GLWESecretKey[T]{body: glweKeyBody}

	return Encrypter[T]{
		params: params,

		uniformSampler: uniformSampler,
		lweSampler:     lweSampler,
		glweSampler:    glweSampler,

		polyEvaluator: poly.NewEvaluater[T](params.PolyDegree),

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

// EncryptLWE encrypts the message to LWE ciphertext.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) EncryptLWE(msg int) LWECiphertext[T] {
	pt := T(msg * e.params.Delta)

	// ct = (a_1, ..., a_n, b = <a, s> + Δm + e)
	ct := LWECiphertext[T]{body: e.uniformSampler.SampleSlice(e.params.LWEDimension)}
	ct.mask = vec.Dot(ct.body, e.lweKey.body) + pt + e.lweSampler.Sample()

	return ct
}

// DecryptLWE decrypts the LWE ciphertext to message.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) int {
	// msg = round(b - <a, s> / Delta)
	pt := ct.mask - vec.Dot(ct.body, e.lweKey.body)
	msg := int(num.RoundRatio(pt, T(e.params.Delta)))

	return msg
}

// EncryptGLWE encrypts the packed messages to GLWE ciphertext.
func (e Encrypter[T]) EncryptGLWE(msgs []int) GLWECiphertext[T] {
	if len(msgs) > e.params.PolyDegree {
		panic("too many messages")
	}

	pt := poly.New[T](e.params.PolyDegree)
	for i, m := range msgs {
		pt.Coeffs[i] = T(m * e.params.Delta)
	}

	// ct = (a_1, ..., a_k, b = sum a*s + Δm + e)
	ct := NewGLWECiphertext(e.params)
	for i := 0; i < e.params.GLWEDimension; i++ {
		ct.body[i] = poly.Poly[T]{Coeffs: e.uniformSampler.SampleSlice(e.params.PolyDegree)}
	}

	for i := 0; i < e.params.GLWEDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.body[i], e.glweKey.body[i], ct.mask)
	}
	e.polyEvaluator.AddAssign(pt, ct.mask)
	e.polyEvaluator.AddAssign(poly.Poly[T]{Coeffs: e.glweSampler.SampleSlice(e.params.PolyDegree)}, ct.mask)

	return ct
}

// DecryptGLWE decrypts the GLWE ciphertext to slice of messages.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	// msg = round(b - sum a*s / Delta)
	pt := ct.mask.Copy()
	for i := 0; i < e.params.GLWEDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.body[i], e.glweKey.body[i], pt)
	}

	msgs := make([]int, e.params.PolyDegree)
	for i := 0; i < e.params.PolyDegree; i++ {
		msgs[i] = int(num.RoundRatio(pt.Coeffs[i], T(e.params.Delta)))
	}
	return msgs
}
