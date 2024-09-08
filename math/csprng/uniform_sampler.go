package csprng

import (
	"crypto/rand"

	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"golang.org/x/crypto/blake2b"
)

// UniformSampler samples values from uniform distribution.
// This uses blake2b as a underlying prng.
type UniformSampler[T num.Integer] struct {
	prng blake2b.XOF

	// The length of the buffer is decided heuristically:
	//
	//  - If SizeT <=16, len(buf) = ByteSizeT * 512
	//  - If SizeT = 32, BufferSize = 4 bytes * 1024 = 4096
	//  - If SizeT = 64, BufferSize = 8 bytes * 2048 = 16384
	buf []byte
	ptr int

	byteSizeT int
	maxT      T
}

// NewUniformSampler allocates an empty UniformSampler.
//
// Panics when read from crypto/rand or blake2b initialization fails.
func NewUniformSampler[T num.Integer]() *UniformSampler[T] {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return NewUniformSamplerWithSeed[T](seed)
}

// NewUniformSamplerWithSeed allocates an empty UniformSampler, with user supplied seed.
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

	byteSizeT := num.ByteSizeT[T]()
	bufSize := 0
	switch byteSizeT {
	case 1, 2:
		bufSize = byteSizeT * 512
	case 4:
		bufSize = byteSizeT * 1024
	case 8:
		bufSize = byteSizeT * 2048
	}

	return &UniformSampler[T]{
		prng: prng,

		buf: make([]byte, bufSize),
		ptr: bufSize,

		byteSizeT: byteSizeT,
		maxT:      T(num.MaxT[T]()),
	}
}

// Sample uniformly samples a random integer of type T.
func (s *UniformSampler[T]) Sample() T {
	if s.ptr == len(s.buf) {
		if _, err := s.prng.Read(s.buf); err != nil {
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

// SampleSliceAssign samples uniform values to vOut.
func (s *UniformSampler[T]) SampleSliceAssign(vOut []T) {
	for i := range vOut {
		vOut[i] = s.Sample()
	}
}

// SamplePolyAssign samples uniform values to p.
func (s *UniformSampler[T]) SamplePolyAssign(pOut poly.Poly[T]) {
	s.SampleSliceAssign(pOut.Coeffs)
}
