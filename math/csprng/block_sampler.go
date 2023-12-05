package csprng

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/vec"
)

// BlockSampler samples values from block binary distribution.
// It samples one of the vectors from (0, ..., 0), (1, ..., 0), ..., (0, .., 1).
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
func (s BlockSampler[T]) SampleSliceAssign(v []T) {
	leftover := len(v) % s.BlockSize
	end := s.BlockSize * (len(v) / s.BlockSize)

	for i := 0; i < end; i += s.BlockSize {
		vec.Fill(v[i:i+s.BlockSize], 0)
		offset := s.baseSampler.SampleN(s.BlockSize + 1)
		if offset != s.BlockSize {
			v[i+offset] = 1
		}
	}

	if leftover != 0 {
		vec.Fill(v[end:end+leftover], 0)
		offset := s.baseSampler.SampleN(leftover + 1)
		if offset != leftover {
			v[end+offset] = 1
		}
	}
}
