package csprng_test

import (
	"math"
	"testing"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/vec"
	"github.com/stretchr/testify/assert"
)

func meanStdDev(v []float64) (mean, stdDev float64) {
	sum := 0.0
	for _, x := range v {
		sum += x
	}

	mean = sum / float64(len(v))

	variance := 0.0
	for _, x := range v {
		variance += (x - mean) * (x - mean)
	}
	stdDev = math.Sqrt(variance / float64(len(v)))

	return
}

func TestGaussianSampler(t *testing.T) {
	mean := 0.0
	sigma := math.Exp2(16)

	gs := csprng.NewGaussianSampler[int64]()
	samples := make([]int64, 1024)
	gs.SampleVecAssign(sigma, samples)
	samplesFloat := vec.Cast[int64, float64](samples)
	meanSample, stdDevSample := meanStdDev(samplesFloat)

	k := 3.29 // From the GLITCH test suite
	N := float64(len(samples))
	meanBound := meanSample + k*stdDevSample/math.Sqrt(N)
	stdDevBound := stdDevSample + k*stdDevSample/math.Sqrt(2*(N-1))

	assert.GreaterOrEqual(t, meanBound, mean)
	assert.GreaterOrEqual(t, stdDevBound, sigma)
}
