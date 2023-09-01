package csprng

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"

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
}

// NewUniformSampler creates a new UniformSampler.
// Unlike WithSeed variant, this function uses crypto/rand.
func NewUniformSampler[T num.Integer]() UniformSampler[T] {
	return UniformSampler[T]{
		prng: bufio.NewReader(rand.Reader),
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
	}
}

// Read implements the io.Reader interface.
// This is a simple wrapping of underlying blake2x prng.
func (s UniformSampler[T]) Read(b []byte) (n int, err error) {
	return s.prng.Read(b)
}

// Sample uniformly samples a random integer of type T.
func (s UniformSampler[T]) Sample() T {
	var buf uint64
	if err := binary.Read(s, binary.BigEndian, &buf); err != nil {
		panic(err)
	}
	return T(buf)
}

// SampleN uniformly samples a random integer of type T in [0, N).
func (s UniformSampler[T]) SampleN(N T) T {
	maxT := T(num.MaxT[T]())
	bound := maxT - (maxT % N)

	for {
		res := num.Abs(s.Sample())
		if res < bound {
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
