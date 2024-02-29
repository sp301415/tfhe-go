package csprng

import (
	"bufio"
	"crypto/rand"

	"github.com/sp301415/tfhe-go/math/num"
	"golang.org/x/crypto/blake2b"
)

// UniformSampler samples values from uniform distribution.
// This uses blake2b as a underlying prng.
type UniformSampler[T num.Integer] struct {
	prng *bufio.Reader

	maxT T
	buf  []byte
}

// NewUniformSampler allocates an empty UniformSampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewUniformSampler[T num.Integer]() UniformSampler[T] {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return NewUniformSamplerWithSeed[T](seed)
}

// NewUniformSamplerWithSeed allocates an empty UniformSampler, with user supplied seed.
//
// Panics when blake2b initialization fails.
func NewUniformSamplerWithSeed[T num.Integer](seed []byte) UniformSampler[T] {
	prng, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	if _, err = prng.Write(seed); err != nil {
		panic(err)
	}

	return UniformSampler[T]{
		prng: bufio.NewReader(prng),

		maxT: T(num.MaxT[T]()),
		buf:  make([]byte, num.SizeT[T]()/8),
	}
}

// Sample uniformly samples a random integer of type T.
func (s UniformSampler[T]) Sample() T {
	if _, err := s.prng.Read(s.buf); err != nil {
		panic(err)
	}

	var res T
	switch len(s.buf) {
	case 1:
		res = T(uint64(s.buf[0]))
	case 2:
		res = T(uint64(s.buf[0]))
		res |= T(uint64(s.buf[1]) << 8)
	case 4:
		res = T(uint64(s.buf[0]))
		res |= T(uint64(s.buf[1]) << 8)
		res |= T(uint64(s.buf[2]) << 16)
		res |= T(uint64(s.buf[3]) << 24)
	case 8:
		res = T(uint64(s.buf[0]))
		res |= T(uint64(s.buf[1]) << 8)
		res |= T(uint64(s.buf[2]) << 16)
		res |= T(uint64(s.buf[3]) << 24)
		res |= T(uint64(s.buf[4]) << 32)
		res |= T(uint64(s.buf[5]) << 40)
		res |= T(uint64(s.buf[6]) << 48)
		res |= T(uint64(s.buf[7]) << 56)
	}
	return res
}

// SampleN uniformly samples a random integer of type T in [0, N).
func (s UniformSampler[T]) SampleN(N T) T {
	bound := s.maxT - (s.maxT % N)
	for {
		res := s.Sample()
		if 0 <= res && res < bound {
			return res % N
		}
	}
}

// SampleSliceAssign samples uniform values to v.
func (s UniformSampler[T]) SampleSliceAssign(v []T) {
	for i := range v {
		v[i] = s.Sample()
	}
}
