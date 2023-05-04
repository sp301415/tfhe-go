package rand

import (
	"crypto/rand"
	"encoding/binary"
	"math"

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
func (s UniformSampler[T]) Sample() T {
	var sample T
	binary.Read(s, binary.BigEndian, &sample)
	return sample
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
