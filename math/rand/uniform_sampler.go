package rand

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	"github.com/sp301415/tfhe/math/num"
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

// SampleVec uniformly samples a length n slice.
func (s UniformSampler[T]) SampleSlice(n int) []T {
	samples := make([]T, n)
	for i := range samples {
		samples[i] = s.Sample()
	}
	return samples
}

// SampleBinarySlice uniformly samples a length n binary slice.
func (s UniformSampler[T]) SampleBinarySlice(n int) []T {
	l := num.Log2(num.MaxT[T]())
	samples := make([]T, n)
	for i := 0; i < n; i += l {
		for j := 0; j < l; j++ {
			idx := i + j
			if idx >= n {
				break
			}
			samples[idx] = (s.Sample() >> j) & 1
		}
	}
	return samples
}
