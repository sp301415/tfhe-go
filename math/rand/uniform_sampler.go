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

// SampleSlice samples uniform values to v.
func (s UniformSampler[T]) SampleSlice(v []T) {
	for i := range v {
		v[i] = s.Sample()
	}
}

// SamplePoly samples a polynomial from uniform distribution.
func (s UniformSampler[T]) SamplePoly(p poly.Poly[T]) {
	for i := range p.Coeffs {
		p.Coeffs[i] = s.Sample()
	}
}
