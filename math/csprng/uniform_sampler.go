package csprng

import (
	"bufio"
	"crypto/rand"
	"unsafe"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/crypto/blake2b"
)

// UniformSampler samples values from uniform distribution.
// For NewUniformSampler, this uses crypto/rand,
// and for NewUniformSamplerWithSeed, this uses blake2b.
//
// Methods of UniformSampler may panic when read from
// crypto/rand or blake2b.XOF fails.
// In practice, it almost never happens especially when
// the seed is automatically supplied using NewUniformSampler.
type UniformSampler[T num.Integer] struct {
	prng *bufio.Reader

	sizeT int
	maxT  T
}

// NewUniformSampler creates a new UniformSampler.
// Unlike WithSeed variant, this function uses crypto/rand.
func NewUniformSampler[T num.Integer]() UniformSampler[T] {
	return UniformSampler[T]{
		prng: bufio.NewReader(rand.Reader),

		sizeT: num.SizeT[T](),
		maxT:  T(num.MaxT[T]()),
	}
}

// NewUniformSamplerWithSeed creates a new UniformSampler, with user supplied seed.
// This uses blake2b as the underlying CSPRNG.
// Note that retreiving the seed after initialization is not possible.
//
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
// This is a simple wrapping of underlying blake2x prng.
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
