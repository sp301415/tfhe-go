package csprng

import (
	"github.com/sp301415/tfhe-go/math/num"
)

// BlockSampler samples values from block binary distribution.
// It samples one of the vectors from (0, ..., 0), (1, ..., 0), ..., (0, .., 1).
//
// See csprng.UniformSampler for more details.
type BlockSampler[T num.Integer] struct {
	baseSampler UniformSampler[int]

	BlockSize int
}

// NewBlockSampler creates a new BlockSampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewBlockSampler[T num.Integer](blockSize int) BlockSampler[T] {
	return BlockSampler[T]{
		baseSampler: NewUniformSampler[int](),
		BlockSize:   blockSize,
	}
}

// NewBlockSamplerWithSeed creates a new BlockSampler, with user supplied seed.
// Note that retreiving the seed after initialization is not possible.
//
// Panics when blake2b initialization fails,
// or blockSize <= 0.
func NewBlockSamplerWithSeed[T num.Integer](seed []byte, blockSize int) BlockSampler[T] {
	return BlockSampler[T]{
		baseSampler: NewUniformSamplerWithSeed[int](seed),
		BlockSize:   blockSize,
	}
}

// SampleSliceAssign samples block binary values to v.
//
// Panics when len(v) % BlockSize != 0.
func (s BlockSampler[T]) SampleSliceAssign(v []T) {
	if len(v)%s.BlockSize != 0 {
		panic("length not multiple of blocksize")
	}

	for i := 0; i < len(v); i += s.BlockSize {
		for j := i; j < i+s.BlockSize; j++ {
			v[j] = 0
		}

		x := s.baseSampler.SampleN(s.BlockSize + 1)
		if x == s.BlockSize {
			continue
		}
		v[i+x] = 1
	}
}
