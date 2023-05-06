package rand

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	"github.com/sp301415/tfhe/math/poly"
	"golang.org/x/exp/constraints"
)

// UniformSampler is a struct for sampling from uniform distribution.
type UniformSampler[T constraints.Integer] struct{}

// Read implements the io.Reader interface.
// This is a wrapper of crypto/rand.Read().
func (s UniformSampler[T]) Read(b []byte) (n int, err error) {
	return rand.Read(b)
}

// Sample uniformly samples a random integer.
// Panics when error occurs from crypto/rand.Read(), but this is highly unlikely.
func (s UniformSampler[T]) Sample() T {
	var sample uint64
	err := binary.Read(s, binary.BigEndian, &sample)
	if err != nil {
		panic(err)
	}

	return T(sample)
}

// SampleRange uniformly samples a random integer from [a, b).
func (s UniformSampler[T]) SampleRange(a, b T) T {
	if a >= b {
		panic("malformed range")
	}

	max := uint64(b - a)
	randMax := math.MaxUint64 - (math.MaxUint64 % max)

	for {
		res := uint64(s.Sample())
		if res <= randMax {
			return T(res%max) + a
		}
	}
}

// SampleSlice returns a slice of length n from uniform distribuition.
func (s UniformSampler[T]) SampleSlice(n int) []T {
	vec := make([]T, n)
	for i := range vec {
		vec[i] = s.Sample()
	}
	return vec
}

// SamplePoly returns a polynomial of degree N from uniform distribution.
// N should be power of two.
func (s UniformSampler[T]) SamplePoly(N int) poly.Poly[T] {
	return poly.From(s.SampleSlice(N))
}
