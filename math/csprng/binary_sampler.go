package csprng

import (
	"github.com/sp301415/tfhe-go/math/num"
)

// BinarySampler samples values from uniform binary distribution {0, 1}.
type BinarySampler[T num.Integer] struct {
	baseSampler UniformSampler[uint64]
}

// NewBinarySampler creates a new BinarySampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewBinarySampler[T num.Integer]() BinarySampler[T] {
	return BinarySampler[T]{
		baseSampler: NewUniformSampler[uint64](),
	}
}

// NewBinarySamplerWithSeed creates a new BinarySampler, with user supplied seed.
//
// Panics when blake2b initialization fails.
func NewBinarySamplerWithSeed[T num.Integer](seed []byte) BinarySampler[T] {
	return BinarySampler[T]{
		baseSampler: NewUniformSamplerWithSeed[uint64](seed),
	}
}

// Sample uniformly samples a random binary integer.
func (s BinarySampler[T]) Sample() T {
	return T(s.baseSampler.Sample() & 1)
}

// SampleSliceAssign samples uniform binary values to v.
func (s BinarySampler[T]) SampleSliceAssign(v []T) {
	var buf uint64
	for i := 0; i < len(v); i++ {
		if i&63 == 0 {
			buf = s.baseSampler.Sample()
		}
		v[i] = T(buf & 1)
		buf >>= 1
	}
}
