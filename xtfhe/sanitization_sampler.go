package xtfhe

import (
	"math"
	"sort"

	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

const (
	// GaussianTailCut is the tail cut for the Gaussian sampler.
	// Essentially, for a Gaussian variable x,
	// center - tailCut * stdDev <= x <= center + tailCut * stdDev
	// with overwhelming probability.
	GaussianTailCut = 12
)

// CDTSampler samples from a discrete Gaussian distribution
// with a fixed center and standard deviation.
type CDTSampler[T num.Integer] struct {
	baseSampler *csprng.UniformSampler[uint64]

	center float64
	stdDev float64

	table  []uint64
	offset int64
}

// NewCDTSampler creates a new CDTSampler.
func NewCDTSampler[T num.Integer](center float64, stdDev float64) *CDTSampler[T] {
	cFloor := math.Floor(center)
	cFrac := center - cFloor

	tailLo := int64(math.Floor(center - GaussianTailCut*stdDev))
	tailHi := int64(math.Ceil(center + GaussianTailCut*stdDev))
	tableSize := tailHi - tailLo + 1

	table := make([]uint64, tableSize)
	cdf := 0.0
	for i, x := 0, tailLo; x <= tailHi; i, x = i+1, x+1 {
		xf := float64(x)
		cdf += math.Exp(-(xf-cFrac)*(xf-cFrac)/(2*stdDev*stdDev)) / (math.Sqrt(2*math.Pi) * stdDev)
		if cdf >= 1 {
			table[i] = math.MaxUint64
		} else {
			table[i] = uint64(cdf * math.MaxUint64)
		}
	}

	return &CDTSampler[T]{
		baseSampler: csprng.NewUniformSampler[uint64](),

		center: center,
		stdDev: stdDev,

		table:  table,
		offset: tailLo + int64(cFloor),
	}
}

// Center returns the center of the Gaussian distribution.
func (s *CDTSampler[T]) Center() float64 {
	return s.center
}

// StdDev returns the standard deviation of the Gaussian distribution.
func (s *CDTSampler[T]) StdDev() float64 {
	return s.stdDev
}

// Sample samples from the discrete Gaussian distribution.
func (s *CDTSampler[T]) Sample() T {
	r := s.baseSampler.Sample()

	x := sort.Search(len(s.table), func(i int) bool {
		return s.table[i] > r
	})

	return T(int64(x) + s.offset)
}

// SampleSliceAssign samples Gaussian values and writes it to vOut.
func (s *CDTSampler[T]) SampleSliceAssign(vOut []T) {
	for i := range vOut {
		vOut[i] = s.Sample()
	}
}

// SamplePolyAssign samples Gaussian values and writes it to pOut.
func (s *CDTSampler[T]) SamplePolyAssign(pOut poly.Poly[T]) {
	s.SampleSliceAssign(pOut.Coeffs)
}

// SamplePolyAddAssign samples Gaussian values and adds to pOut.
func (s *CDTSampler[T]) SamplePolyAddAssign(pOut poly.Poly[T]) {
	for i := range pOut.Coeffs {
		pOut.Coeffs[i] += s.Sample()
	}
}

// SamplePolySubAssign samples Gaussian values and subtracts from pOut.
func (s *CDTSampler[T]) SamplePolySubAssign(pOut poly.Poly[T]) {
	for i := range pOut.Coeffs {
		pOut.Coeffs[i] -= s.Sample()
	}
}
