package num_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/csprng"
	"github.com/sp301415/tfhe/math/num"
)

var res uint64 // Prevent compiler optimizations

// We benchmark some hot paths here
func BenchmarkRoundRatio(b *testing.B) {
	s := csprng.NewUniformSamplerWithSeed[uint64](nil)

	sampleCount := 1024
	samples := s.SampleSlice(sampleCount)

	logN := 15
	N := uint64(1 << logN)

	b.Run("RoundRatio", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range samples {
				res = num.RoundRatio(s, N)
			}
		}
	})

	b.Run("RoundRatioBits", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range samples {
				res = num.RoundRatioBits(s, logN)
			}
		}
	})
}
