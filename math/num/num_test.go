package num_test

import (
	"testing"

	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/rand"
)

var res uint64 // Prevent compiler optimizations

// We benchmark some hot paths here
func BenchmarkRoundRatio(b *testing.B) {
	sampleCount := 1024
	samples := make([]uint64, sampleCount)
	rand.UniformSampler[uint64]{}.SampleSlice(samples)

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
