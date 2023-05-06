package rand

import (
	"crypto/rand"

	"github.com/sp301415/tfhe/math/poly"
	"golang.org/x/exp/constraints"
)

// BinarySampler is a struct for sampling from binary distribution.
type BinarySampler[T constraints.Integer] struct {
	buf [1]byte
}

// Read implements the io.Reader interface.
// This is a wrapper of crypto/rand.Read().
func (s BinarySampler[T]) Read(b []byte) (n int, err error) {
	for i := 0; i < len(b); i += 8 {
		_, err = rand.Read(s.buf[:])
		if err != nil {
			return
		}

		for j := 0; j < 8; j++ {
			n = i + j
			if n >= len(b) {
				break
			}

			b[n] = (s.buf[0] >> j) & 1
		}
	}
	return
}

// Sample uniformly samples a random binary integer.
// Panics when error occurs from crypto/rand.Read(), but this is highly unlikely.
func (s BinarySampler[T]) Sample() T {
	if s.buf[0] == 0 {
		_, err := s.Read(s.buf[:])
		if err != nil {
			panic(err)
		}
	}

	sample := T(s.buf[0] & 1)
	s.buf[0] >>= 1
	return sample
}

// SampleSlice samples uniform binary values to v.
func (s BinarySampler[T]) SampleSlice(v []T) {
	for i := range v {
		v[i] = s.Sample()
	}
}

// SamplePoly samples a polynomial from uniform binary distribution.
func (s BinarySampler[T]) SamplePoly(p poly.Poly[T]) {
	for i := range p.Coeffs {
		p.Coeffs[i] = s.Sample()
	}
}
