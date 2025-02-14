package csprng

import (
	"crypto/rand"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/crypto/blake2b"
)

// bufSize is the default buffer size of UniformSampler.
const bufSize = 8192

// UniformSampler samples values from uniform distribution.
// This uses blake2b as a underlying prng.
type UniformSampler[T num.Integer] struct {
	prng blake2b.XOF

	buf [bufSize]byte
	ptr int

	byteSizeT int
	maxT      T
}

// NewUniformSampler creates a new UniformSampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewUniformSampler[T num.Integer]() *UniformSampler[T] {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return NewUniformSamplerWithSeed[T](seed)
}

// NewUniformSamplerWithSeed creates a new UniformSampler, with user supplied seed.
//
// Panics when blake2b initialization fails.
func NewUniformSamplerWithSeed[T num.Integer](seed []byte) *UniformSampler[T] {
	prng, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	if _, err = prng.Write(seed); err != nil {
		panic(err)
	}

	return &UniformSampler[T]{
		prng: prng,

		buf: [bufSize]byte{},
		ptr: bufSize,

		byteSizeT: num.ByteSizeT[T](),
		maxT:      T(num.MaxT[T]()),
	}
}

// Sample uniformly samples a random integer of type T.
func (s *UniformSampler[T]) Sample() T {
	if s.ptr == len(s.buf) {
		if _, err := s.prng.Read(s.buf[:]); err != nil {
			panic(err)
		}
		s.ptr = 0
	}

	var res T
	switch s.byteSizeT {
	case 1:
		res = T(uint64(s.buf[s.ptr+0]))
	case 2:
		res = T(uint64(s.buf[s.ptr+0]))
		res |= T(uint64(s.buf[s.ptr+1]) << 8)
	case 4:
		res = T(uint64(s.buf[s.ptr+0]))
		res |= T(uint64(s.buf[s.ptr+1]) << 8)
		res |= T(uint64(s.buf[s.ptr+2]) << 16)
		res |= T(uint64(s.buf[s.ptr+3]) << 24)
	case 8:
		res = T(uint64(s.buf[s.ptr+0]))
		res |= T(uint64(s.buf[s.ptr+1]) << 8)
		res |= T(uint64(s.buf[s.ptr+2]) << 16)
		res |= T(uint64(s.buf[s.ptr+3]) << 24)
		res |= T(uint64(s.buf[s.ptr+4]) << 32)
		res |= T(uint64(s.buf[s.ptr+5]) << 40)
		res |= T(uint64(s.buf[s.ptr+6]) << 48)
		res |= T(uint64(s.buf[s.ptr+7]) << 56)
	}
	s.ptr += s.byteSizeT

	return res
}

// SampleN uniformly samples a random integer of type T in [0, N).
func (s *UniformSampler[T]) SampleN(N T) T {
	bound := s.maxT - (s.maxT % N)
	for {
		res := s.Sample()
		if 0 <= res && res < bound {
			return res % N
		}
	}
}

// SampleVecAssign samples uniform values to vOut.
func (s *UniformSampler[T]) SampleVecAssign(vOut []T) {
	for i := range vOut {
		vOut[i] = s.Sample()
	}
}

// SamplePolyAssign samples uniform values to p.
func (s *UniformSampler[T]) SamplePolyAssign(pOut poly.Poly[T]) {
	s.SampleVecAssign(pOut.Coeffs)
}
