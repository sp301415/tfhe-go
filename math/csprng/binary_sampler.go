package csprng

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/math/vec"
)

// BinarySampler samples values from uniform and block binary distribution.
type BinarySampler[T num.Integer] struct {
	baseSampler *UniformSampler[uint64]
}

// NewBinarySampler creates a new BinarySampler.
//
// Panics when read from crypto/rand or AES initialization fails.
func NewBinarySampler[T num.Integer]() *BinarySampler[T] {
	return &BinarySampler[T]{
		baseSampler: NewUniformSampler[uint64](),
	}
}

// NewBinarySamplerWithSeed creates a new BinarySampler, with user supplied seed.
//
// Panics when AES initialization fails.
func NewBinarySamplerWithSeed[T num.Integer](seed []byte) *BinarySampler[T] {
	return &BinarySampler[T]{
		baseSampler: NewUniformSamplerWithSeed[uint64](seed),
	}
}

// Sample uniformly samples a random binary integer.
func (s *BinarySampler[T]) Sample() T {
	return T(s.baseSampler.Sample() & 1)
}

// SampleVecTo samples uniform binary values to vOut.
func (s *BinarySampler[T]) SampleVecTo(vOut []T) {
	var buf uint64
	for i := 0; i < len(vOut); i++ {
		if i&63 == 0 {
			buf = s.baseSampler.Sample()
		}
		vOut[i] = T(buf & 1)
		buf >>= 1
	}
}

// SamplePolyTo samples uniform binary values to pOut.
func (s *BinarySampler[T]) SamplePolyTo(pOut poly.Poly[T]) {
	s.SampleVecTo(pOut.Coeffs)
}

// SampleBlockVecTo samples block binary values to vOut.
func (s *BinarySampler[T]) SampleBlockVecTo(vOut []T, blockSize int) {
	if len(vOut)%blockSize != 0 {
		panic("SampleBlockVecTo: length not multiple of blocksize")
	}

	for i := 0; i < len(vOut); i += blockSize {
		vec.Fill(vOut[i:i+blockSize], 0)
		offset := int(s.baseSampler.SampleN(uint64(blockSize) + 1))
		if offset == blockSize {
			continue
		}
		vOut[i+offset] = 1
	}
}

// SampleBlockPolyTo samples block binary values to pOut.
func (s *BinarySampler[T]) SampleBlockPolyTo(pOut poly.Poly[T], blockSize int) {
	s.SampleBlockVecTo(pOut.Coeffs, blockSize)
}
