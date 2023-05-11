package csprng

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
	"golang.org/x/crypto/blake2b"
)

// UniformSampler samples values from uniform distribution.
// It uses Blake2x as the underlying CSPRNG.
//
// Methods of UniformSampler may panic when read from
// crypto/rand or blake2b.XOF fails.
// In practice, it almost never happens especially when
// the seed is automatically supplied using NewUniformSampler.
type UniformSampler[T num.Integer] struct {
	prng blake2b.XOF
}

// NewUniformSampler creates a new UniformSampler.
// The seed is sampled securely from crypto/rand,
// so it may panic if read from crypto/rand fails.
func NewUniformSampler[T num.Integer]() UniformSampler[T] {
	// Sample 512-bit seed
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	// This never panics, because the only case when NewXOF returns error
	// is when key size is too large.
	return NewUniformSamplerWithSeed[T](seed)
}

// NewUniformSamplerWithSeed creates a new UniformSampler, with user supplied seed.
// Note that retreiving the seed after initialization is not possible.
//
// Panics when blake2b initialization fails.
func NewUniformSamplerWithSeed[T num.Integer](seed []byte) UniformSampler[T] {
	prng, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed)
	if err != nil {
		panic(err)
	}

	return UniformSampler[T]{
		prng: prng,
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

// SampleSliceAssign samples uniform values to v.
func (s UniformSampler[T]) SampleSliceAssign(v []T) {
	for i := range v {
		v[i] = s.Sample()
	}
}

// SampleSlice returns uniformly sampled slice of length n.
func (s UniformSampler[T]) SampleSlice(n int) []T {
	v := make([]T, n)
	s.SampleSliceAssign(v)
	return v
}

// SamplePolyAssign samples a polynomial from uniform distribution.
func (s UniformSampler[T]) SamplePolyAssign(p poly.Poly[T]) {
	s.SampleSliceAssign(p.Coeffs)
}

// SamplePoly returns uniformly sampled polynomial of degree N.
func (s UniformSampler[T]) SamplePoly(N int) poly.Poly[T] {
	p := poly.New[T](N)
	s.SamplePolyAssign(p)
	return p
}
