package csprng

import (
	"crypto/rand"
	"math"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
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

		StdDev: stdDev,
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

// NormFloat2 samples two float64 values from normal distribution.
func (s GaussianSampler[T]) NormFloat2() (float64, float64) {
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

// NormFloat samples float64 value from normal distribution.
func (s GaussianSampler[T]) NormFloat() float64 {
	u, _ := s.NormFloat2()
	return u
}

// Sample2 returns a pair of numbers sampled from rounded gaussian distribution.
func (s GaussianSampler[T]) Sample2() (T, T) {
	u, v := s.NormFloat2()
	return T(math.Round(u * s.StdDev)), T(math.Round(v * s.StdDev))
}

// Sample returns a number sampled from rounded gaussian distribution.
func (s GaussianSampler[T]) Sample() T {
	u, _ := s.Sample2()
	return u
}

// SampleSliceAssign samples rounded gaussian values to v.
func (s GaussianSampler[T]) SampleSliceAssign(v []T) {
	for i := 0; i < len(v); i += 2 {
		v[i], v[i+1] = s.Sample2()
	}
	if len(v)%2 != 0 {
		v[len(v)-1] = s.Sample()
	}
}

// SampleSlice returns sampled rounded gaussian slice of length n.
func (s GaussianSampler[T]) SampleSlice(n int) []T {
	v := make([]T, n)
	s.SampleSliceAssign(v)
	return v
}

// SamplePolyAssign samples a polynomial rounded from gaussian distribution.
func (s GaussianSampler[T]) SamplePolyAssign(p poly.Poly[T]) {
	s.SampleSliceAssign(p.Coeffs)
}

// SamplePolyAddAssign samples a polynomial from rounded gaussian distribution
// and adds it to p.
func (s GaussianSampler[T]) SamplePolyAddAssign(p poly.Poly[T]) {
	for i := range p.Coeffs {
		p.Coeffs[i] += s.Sample()
	}
}

// SamplePoly returns sampled rounded gaussian polynomial of degree N.
func (s GaussianSampler[T]) SamplePoly(N int) poly.Poly[T] {
	p := poly.New[T](N)
	s.SamplePolyAssign(p)
	return p
}
