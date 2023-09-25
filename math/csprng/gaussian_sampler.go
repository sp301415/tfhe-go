package csprng

import (
	"math"

	"github.com/sp301415/tfhe-go/math/num"
)

// GaussianSampler samples from Rounded Gaussian Distribution, centered around zero.
//
// See csprng.UniformSampler for more details.
type GaussianSampler[T num.Integer] struct {
	baseSampler UniformSampler[int32]

	StdDev float64
}

// NewGaussianSampler creates a new GaussianSampler.
// Panics when read from crypto/rand or blake2b initialization fails, or StdDev <= 0.
func NewGaussianSampler[T num.Integer](stdDev float64) GaussianSampler[T] {
	if stdDev <= 0 {
		panic("StdDev smaller than zero")
	}

	return GaussianSampler[T]{
		baseSampler: NewUniformSampler[int32](),
		StdDev:      stdDev,
	}
}

// NewGaussianSamplerWithSeed creates a new GaussianSampler, with user supplied seed.
// Panics when blake2b initialization fails or StdDev <= 0.
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

// Sample returns a number sampled from rounded gaussian distribution.
func (s GaussianSampler[T]) Sample() T {
	u, _ := s.normFloat2()
	u = math.Round(u)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		return T(int(u))
	case uint8:
		return T(int8(u))
	case uint16:
		return T(int16(u))
	case uint32:
		return T(int32(u))
	case uint64:
		return T(int64(u))
	}
	return T(u)
}

// SampleSliceAssign samples rounded gaussian values to v.
func (s GaussianSampler[T]) SampleSliceAssign(v []T) {
	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(int(math.Round(x)))
			v[i+1] = T(int(math.Round(y)))
		}
	case uint8:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(int8(math.Round(x)))
			v[i+1] = T(int8(math.Round(y)))
		}
	case uint16:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(int16(math.Round(x)))
			v[i+1] = T(int16(math.Round(y)))
		}
	case uint32:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(int32(math.Round(x)))
			v[i+1] = T(int32(math.Round(y)))
		}
	case uint64:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(int64(math.Round(x)))
			v[i+1] = T(int64(math.Round(y)))
		}
	default:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] = T(math.Round(x))
			v[i+1] = T(math.Round(y))
		}
	}

	if len(v)%2 != 0 {
		v[len(v)-1] = s.Sample()
	}
}

// SampleSliceAddAssign samples rounded gaussian values and adds to v.
// Mostly used in EncryptBody functions, adding noise to the message.
func (s GaussianSampler[T]) SampleSliceAddAssign(v []T) {
	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(int(math.Round(x)))
			v[i+1] += T(int(math.Round(y)))
		}
	case uint8:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(int8(math.Round(x)))
			v[i+1] += T(int8(math.Round(y)))
		}
	case uint16:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(int16(math.Round(x)))
			v[i+1] += T(int16(math.Round(y)))
		}
	case uint32:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(int32(math.Round(x)))
			v[i+1] += T(int32(math.Round(y)))
		}
	case uint64:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(int64(math.Round(x)))
			v[i+1] += T(int64(math.Round(y)))
		}
	default:
		for i := 0; i < len(v); i += 2 {
			x, y := s.normFloat2()
			v[i] += T(math.Round(x))
			v[i+1] += T(math.Round(y))
		}
	}

	if len(v)%2 != 0 {
		v[len(v)-1] += s.Sample()
	}
}
