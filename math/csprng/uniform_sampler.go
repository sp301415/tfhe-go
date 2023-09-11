package csprng

import (
	"bufio"
	"crypto/rand"
	"unsafe"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/crypto/blake2b"
)

// UniformSampler samples values from uniform distribution.
// This uses blake2b as a underlying prng.
type UniformSampler[T num.Integer] struct {
	prng *bufio.Reader

	sizeT int
	maxT  T
}

// NewUniformSampler creates a new UniformSampler.
// Panics when read from crypto/rand or blake2b initialization fails.
func NewUniformSampler[T num.Integer]() UniformSampler[T] {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return NewUniformSamplerWithSeed[T](seed)
}

// NewUniformSamplerWithSeed creates a new UniformSampler, with user supplied seed.
// Panics when blake2b initialization fails.
func NewUniformSamplerWithSeed[T num.Integer](seed []byte) UniformSampler[T] {
	prng, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed)
	if err != nil {
		panic(err)
	}

	return UniformSampler[T]{
		prng: bufio.NewReader(prng),

		sizeT: num.SizeT[T](),
		maxT:  T(num.MaxT[T]()),
	}
}

// Read implements the io.Reader interface.
// This is a simple wrapping of underlying blake2b prng.
func (s UniformSampler[T]) Read(b []byte) (n int, err error) {
	return s.prng.Read(b)
}

// Sample uniformly samples a random integer of type T.
func (s UniformSampler[T]) Sample() T {
	out := make([]byte, s.sizeT/8)
	if _, err := s.prng.Read(out); err != nil {
		panic(err)
	}

	return *(*T)(unsafe.Pointer(&out[0]))
}

// SampleN uniformly samples a random integer of type T in [0, N).
func (s UniformSampler[T]) SampleN(N T) T {
	bound := s.maxT - (s.maxT % N)
	for {
		res := s.Sample()
		if 0 < res && res < bound {
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
