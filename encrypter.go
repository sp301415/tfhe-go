package tfhe

import (
	"github.com/sp301415/tfhe/internal/num"
	"github.com/sp301415/tfhe/internal/poly"
	"github.com/sp301415/tfhe/internal/rand"
	"github.com/sp301415/tfhe/internal/vec"
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
	lweKey := NewLWESecretKey(params)
	for i := 0; i < lweKey.Len(); i += 32 {
		buf := uniformSampler.Sample()
		for j := 0; j < 32; j++ {
			idx := i + j
			if idx > lweKey.Len()-1 {
				break
			}
			lweKey.value[idx] = (buf >> j) & 1
		}
	}

	// Sample binary GLWE key
	glweKey := NewGLWESecretKey(params)
	for i := 0; i < glweKey.Len(); i++ {
		for j := 0; j < params.PolyDegree; j += 32 {
			buf := uniformSampler.Sample()
			for k := 0; k < 32; k++ {
				idx := j + k
				if idx > params.PolyDegree {
					break
				}
				glweKey.value[i].Coeffs[idx] = (buf >> k) & 1
			}
		}
	}

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

// EncryptLWE encrypts the message to LWE ciphertext.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) EncryptLWE(msg int) LWECiphertext[T] {
	pt := T(msg * e.params.Delta)

	// ct = (a_1, ..., a_n, b = <a, s> + Δm + e)
	ct := NewLWECiphertext(e.params)
	for i := 0; i < e.params.LWEDimension; i++ {
		ct.value[i] = e.uniformSampler.Sample()
	}
	ct.value[ct.Len()-1] = vec.Dot(ct.mask(), e.lweKey.value) + pt + e.lweSampler.Sample()

	return ct
}

// DecryptLWE decrypts the LWE ciphertext to message.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) DecryptLWE(ct LWECiphertext[T]) int {
	// msg = round(b - <a, s> / Delta)
	pt := ct.body() - vec.Dot(ct.mask(), e.lweKey.value)
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
		for j := 0; j < e.params.PolyDegree; j++ {
			ct.value[i].Coeffs[j] = e.uniformSampler.Sample()
		}
	}

	for i := 0; i < e.params.GLWEDimension; i++ {
		e.polyEvaluator.MulAddAssign(ct.value[i], e.glweKey.value[i], ct.value[ct.Len()-1])
	}
	e.polyEvaluator.AddAssign(pt, ct.value[ct.Len()-1])

	err := poly.New[T](e.params.PolyDegree)
	for i := range err.Coeffs {
		err.Coeffs[i] = e.glweSampler.Sample()
	}
	e.polyEvaluator.AddAssign(err, ct.value[ct.Len()-1])

	return ct
}

// DecryptGLWE decrypts the GLWE ciphertext to slice of messages.
//
//	WARNING: This does not handle overflow.
func (e Encrypter[T]) DecryptGLWE(ct GLWECiphertext[T]) []int {
	// msg = round(b - sum a*s / Delta)
	pt := ct.body().Copy()
	for i := 0; i < e.params.GLWEDimension; i++ {
		e.polyEvaluator.MulSubAssign(ct.value[i], e.glweKey.value[i], pt)
	}

	msgs := make([]int, e.params.PolyDegree)
	for i := 0; i < e.params.PolyDegree; i++ {
		msgs[i] = int(num.RoundRatio(pt.Coeffs[i], T(e.params.Delta)))
	}
	return msgs
}
