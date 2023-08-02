package csprng

import (
	"crypto/rand"
	"math"

	"github.com/sp301415/tfhe/math/num"
)

// GaussianSampler samples from Rounded Gaussian Distribution, centered around zero.
//
// See rand.UniformSampler for more details.
type GaussianSampler[T num.Integer] struct {
	baseSampler UniformSampler[int32]

	StdDev float64
}

// NewGaussianSampler creates a new GaussianSampler.
// The seed is sampled securely from crypto/rand,
// so it may panic if read from crypto/rand fails.
//
// Also panics when stdDev <= 0.
func NewGaussianSampler[T num.Integer](stdDev float64) GaussianSampler[T] {
	// Sample 512-bit seed
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	// This never panics, because the only case when NewXOF returns error
	// is when key size is too large.
	return NewGaussianSamplerWithSeed[T](seed, stdDev)
}

// NewGaussianSamplerWithSeed creates a new GaussianSampler, with user supplied seed.
// Note that retreiving the seed after initialization is not possible.
//
// Panics when blake2b initialization fails,
// or stdDev <= 0.
func NewGaussianSamplerWithSeed[T num.Integer](seed []byte, stdDev float64) GaussianSampler[T] {
	if stdDev <= 0 {
		panic("StdDev smaller than zero")
	}

	return GaussianSampler[T]{
		baseSampler: NewUniformSamplerWithSeed[int32](seed),
		StdDev:      stdDev,
	}
}

// NewGaussianSamplerTorus is equivalent to NewGaussianSampler, but stdDev is scaled by 2^SizeT.
func NewGaussianSamplerTorus[T num.Integer](stdDev float64) GaussianSampler[T] {
	maxTf := math.Exp2(float64(num.SizeT[T]()))
	return NewGaussianSampler[T](stdDev * maxTf)
}

// NewGaussianSamplerTorusWithSeed is equivalent to NewGaussianSamplerWithSeed, but stdDev is scaled by 2^SizeT.
func NewGaussianSamplerTorusWithSeed[T num.Integer](seed []byte, stdDev float64) GaussianSampler[T] {
	maxTf := math.Exp2(float64(num.SizeT[T]()))
	return NewGaussianSamplerWithSeed[T](seed, stdDev*maxTf)
}

// uniformFloat samples float64 from uniform distribution in [-1, +1].
func (s GaussianSampler[T]) uniformFloat() float64 {
	return float64(s.baseSampler.Sample()) * math.Exp2(-31)
}

// normFloat2 samples two float64 values from normal distribution.
func (s GaussianSampler[T]) normFloat2() (float64, float64) {
	// Implementation of Polar Box-Muller Transform (https://en.wikipedia.org/wiki/Box–Muller_transform#Polar_form)
	for {
		u, v := s.uniformFloat(), s.uniformFloat()
		r := u*u + v*v
		if 0 < r && r < 1 {
			t := math.Sqrt(-2 * math.Log(r) / r)
			return u * t, v * t
		}
	}
}

// sample2 returns a pair of numbers sampled from rounded gaussian distribution.
func (s GaussianSampler[T]) sample2() (T, T) {
	u, v := s.normFloat2()
	return num.FromFloat64[T](u * s.StdDev), num.FromFloat64[T](v * s.StdDev)
}

// Sample returns a number sampled from rounded gaussian distribution.
func (s GaussianSampler[T]) Sample() T {
	u, _ := s.sample2()
	return u
}

// SampleSliceAssign samples rounded gaussian values to v.
func (s GaussianSampler[T]) SampleSliceAssign(v []T) {
	for i := 0; i < len(v); i += 2 {
		v[i], v[i+1] = s.sample2()
	}
	if len(v)%2 != 0 {
		v[len(v)-1] = s.Sample()
	}
}

// SampleSliceAddAssign samples rounded gaussian values and adds to v.
// Mostly used in EncryptBody functions, adding noise to the message.
func (s GaussianSampler[T]) SampleSliceAddAssign(v []T) {
	for i := 0; i < len(v); i += 2 {
		x, y := s.sample2()
		v[i] += x
		v[i+1] += y
	}
	if len(v)%2 != 0 {
		v[len(v)-1] += s.Sample()
	}
}
