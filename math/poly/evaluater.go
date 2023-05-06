package poly

import (
	"math"
	"math/cmplx"

	"github.com/sp301415/tfhe/math/num"
	"golang.org/x/exp/constraints"
	"gonum.org/v1/gonum/dsp/fourier"
)

// Evaluater calculates polynomial algorithms.
// Most operations have three formats: For example, for Add,
//
//   - Add(p0, p1) returns a new polynomial p = p0 + p1.
//   - AddInPlace(p0, p1, pOut) overrides pOut as p0 + p1.
//   - AddAssign(p0, pOut) overrides pOut as pOut + p0.
type Evaluater[T constraints.Integer] struct {
	// degree is the degree of polynomial that this evaluater can handle.
	degree int

	// fft holds gonum's fourier.FFT.
	fft *fourier.FFT
	// fftHalf holds gonum's fourier.CmplxFFT for N/2. Used for negacyclic convolution.
	fftHalf *fourier.CmplxFFT

	// wj holds the precomputed values of w_2N^j where j = 0 ~ N.
	wj []complex128
	// wjInv holds the precomputed values of w_2N^-j where j = 0 ~ N.
	wjInv []complex128

	/* Buffers */

	// buffp0f saves the coefficients of p0 in float64.
	buffp0f []float64
	//buffp1f saves the coefficients of p1 in float64.
	buffp1f []float64
	// buffpOutf saves the coefficients of pOut in float64.
	buffpOutf []float64

	// buffp0c saves the fourier transform of p0 in convolution.
	buffp0c []complex128
	// buff1c saves the fourier transform of p1 in convolution.
	buffp1c []complex128
}

// NewEvaluater creates a new Evaluater with degree N.
// N should be power of two.
func NewEvaluater[T constraints.Integer](N int) Evaluater[T] {
	if !num.IsPowerOfTwo(N) {
		panic("degree should be power of two")
	}

	wj := make([]complex128, N)
	wjInv := make([]complex128, N)
	for j := 0; j < N/2; j++ {
		e := math.Pi * float64(j) / float64(N)
		wj[j] = cmplx.Exp(complex(0, e))
		wjInv[j] = cmplx.Exp(-complex(0, e))
	}

	return Evaluater[T]{
		degree:  N,
		fft:     fourier.NewFFT(N),
		fftHalf: fourier.NewCmplxFFT(N / 2),

		wj:    wj,
		wjInv: wjInv,

		buffp0f:   make([]float64, N),
		buffp1f:   make([]float64, N),
		buffpOutf: make([]float64, N),

		buffp0c: make([]complex128, N/2),
		buffp1c: make([]complex128, N/2),
	}
}

// Degree returns the degree of polynomial that the evaluater can handle.
func (e Evaluater[T]) Degree() int {
	return e.degree
}
