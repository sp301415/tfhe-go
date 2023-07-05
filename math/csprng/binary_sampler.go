package csprng

import (
	"crypto/rand"

	"github.com/sp301415/tfhe/math/num"
)

// BinarySampler samples values from uniform binary distribution {0, 1}.
// It uses Blake2x as the underlying CSPRNG.
//
// See rand.UniformSampler for more details.
type BinarySampler[T num.Integer] struct {
	baseSampler UniformSampler[uint64]

	// ptr represents the pointer in the buffer.
	// if ptr = 8, new sample is needed.
	ptr int
	// buf is a byte buffer. Length is always 1.
	buf []byte
}

// NewBinarySampler creates a new BinarySampler.
// The seed is sampled securely from crypto/rand,
// so it may panic if read from crypto/rand fails.
func NewBinarySampler[T num.Integer]() BinarySampler[T] {
	// Sample 512-bit seed
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	// This never panics, because the only case when NewXOF returns error
	// is when key size is too large.
	return NewBinarySamplerWithSeed[T](seed)
}

// NewBinarySamplerWithSeed creates a new BinarySampler, with user supplied seed.
// Note that retreiving the seed after initialization is not possible.
//
// Panics when blake2b initialization fails.
func NewBinarySamplerWithSeed[T num.Integer](seed []byte) BinarySampler[T] {
	return BinarySampler[T]{
		baseSampler: NewUniformSampler[uint64](),

		ptr: 0,
		buf: make([]byte, 1),
	}
}

// Read implements the io.Reader interface.
func (s BinarySampler[T]) Read(b []byte) (n int, err error) {
	n, err = s.baseSampler.Read(b)
	if err != nil {
		return
	}

	for i := range b {
		b[i] = b[i] & 1
	}
	return
}

// Sample uniformly samples a random binary integer.
func (s *BinarySampler[T]) Sample() T {
	if s.ptr == 8 {
		if _, err := s.baseSampler.Read(s.buf); err != nil {
			panic(err)
		}
		s.ptr = 0
	}

	sample := T(s.buf[0] & 1)
	s.buf[0] >>= 1
	s.ptr++

	return sample
}

// SampleSliceInPlace samples uniform binary values to v.
func (s BinarySampler[T]) SampleSliceInPlace(v []T) {
	for i := range v {
		v[i] = s.Sample()
	}
}
