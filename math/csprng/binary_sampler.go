package csprng

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// BinarySampler samples values from uniform and block binary distribution.
type BinarySampler[T num.Integer] struct {
	baseSampler UniformSampler[uint64]
}

// NewBinarySampler allocates an empty BinarySampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewBinarySampler[T num.Integer]() BinarySampler[T] {
	return BinarySampler[T]{
		baseSampler: NewUniformSampler[uint64](),
	}
}

// NewBinarySamplerWithSeed allocates an empty BinarySampler, with user supplied seed.
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

// SampleBlockSliceAssign samples block binary values to v.
func (s BinarySampler[T]) SampleBlockSliceAssign(blockSize int, v []T) {
	if len(v)%blockSize != 0 {
		panic("length not multiple of blocksize")
	}

	for i := 0; i < len(v); i += blockSize {
		vec.Fill(v[i:i+blockSize], 0)
		offset := int(s.baseSampler.SampleN(uint64(blockSize) + 1))
		if offset == blockSize {
			continue
		}
		v[i+offset] = 1
	}
}
