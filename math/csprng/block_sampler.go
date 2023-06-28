package csprng

import (
	"crypto/rand"

	"github.com/sp301415/tfhe/math/num"
)

// BlockSampler samples values from block binary distribution.
// It samples one of the vectors from (0, ..., 0), (1, ..., 0), ..., (0, .., 1).
type BlockSampler[T num.Integer] struct {
	baseSampler UniformSampler[int]

	BlockSize int
}

// NewBlockSampler creates a new BlockSampler.
// The seed is sampled securely from crypto/rand,
// so it may panic if read from crypto/rand fails.
//
// Also panics when blockSize <= 0.
func NewBlockSampler[T num.Integer](blockSize int) BlockSampler[T] {
	// Sample 512-bit seed
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	// This never panics, because the only case when NewXOF returns error
	// is when key size is too large.
	return NewBlockSamplerWithSeed[T](seed, blockSize)
}

// NewBinarySamplerWithSeed creates a new BlockSampler, with user supplied seed.
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
// Panics when len(v) % BlockSize != 0.
func (s BlockSampler[T]) SampleSliceAssign(v []T) {
	if len(v)%s.BlockSize != 0 {
		panic("length not multiple of blocksize")
	}

	for i := 0; i < len(v); i += s.BlockSize {
		for j := i; j < i+s.BlockSize; j++ {
			v[j] = 0
		}

		// Sample 0 <= x <= BlockSize
		// and if x = BlockSize, return zero sample
		// otherwise, set sample[x] = 1.
		x := s.baseSampler.SampleRange(0, s.BlockSize+1)
		if x == s.BlockSize {
			continue
		}
		v[i+x] = 1
	}
}

// SampleSlice returns uniformly sampled block binary slice of length n.
// Panics when n % BlockSize != 0.
func (s BlockSampler[T]) SampleSlice(n int) []T {
	v := make([]T, n)
	s.SampleSliceAssign(v)
	return v
}
