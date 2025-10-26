package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Decomposer decomposes a scalar or a polynomial
// according to the gadget parameters.
//
// Decomposer is not safe for concurrent use.
// Use [*Decomposer.SafeCopy] to get a safe copy.
type Decomposer[T TorusInt] struct {
	// PolyEvaluator is a PolyEvaluator for this Decomposer.
	PolyEvaluator *poly.Evaluator[T]

	buf decomposerBuffer[T]
}

// decomposerBuffer is a buffer for Decomposer.
type decomposerBuffer[T TorusInt] struct {
	// cDcmp is the cDcmp scalar.
	cDcmp []T
	// pDcmp is the decomposed polynomial.
	pDcmp []poly.Poly[T]
	// fpDcmp is the decomposed polynomial in Fourier domain.
	fpDcmp []poly.FFTPoly
}

// NewDecomposer creates a new Decomposer.
func NewDecomposer[T TorusInt](N int) *Decomposer[T] {
	return &Decomposer[T]{
		PolyEvaluator: poly.NewEvaluator[T](N),

		buf: decomposerBuffer[T]{},
	}
}

// SafeCopy returns a thread-safe copy.
func (d *Decomposer[T]) SafeCopy() *Decomposer[T] {
	bufCopy := decomposerBuffer[T]{
		cDcmp:  make([]T, len(d.buf.cDcmp)),
		pDcmp:  make([]poly.Poly[T], len(d.buf.pDcmp)),
		fpDcmp: make([]poly.FFTPoly, len(d.buf.fpDcmp)),
	}

	for i := range bufCopy.pDcmp {
		bufCopy.pDcmp[i] = d.PolyEvaluator.NewPoly()
	}
	for i := range bufCopy.fpDcmp {
		bufCopy.fpDcmp[i] = d.PolyEvaluator.NewFFTPoly()
	}

	return &Decomposer[T]{
		PolyEvaluator: d.PolyEvaluator.SafeCopy(),

		buf: bufCopy,
	}
}

// ScalarBuffer returns a internal buffer for scalar decomposition with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) ScalarBuffer(gadgetParams GadgetParameters[T]) []T {
	if len(d.buf.cDcmp) >= gadgetParams.level {
		return d.buf.cDcmp[:gadgetParams.level]
	}

	oldLen := len(d.buf.cDcmp)
	d.buf.cDcmp = append(d.buf.cDcmp, make([]T, gadgetParams.level-oldLen)...)
	return d.buf.cDcmp
}

// PolyBuffer returns a internal buffer for polynomial decomposition with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) PolyBuffer(gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	if len(d.buf.pDcmp) >= gadgetParams.level {
		return d.buf.pDcmp[:gadgetParams.level]
	}

	oldLen := len(d.buf.pDcmp)
	d.buf.pDcmp = append(d.buf.pDcmp, make([]poly.Poly[T], gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		d.buf.pDcmp[i] = d.PolyEvaluator.NewPoly()
	}
	return d.buf.pDcmp
}

// FFTPolyBuffer returns a internal buffer for polynomial decomposition in Fourier domain with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) FFTPolyBuffer(gadgetParams GadgetParameters[T]) []poly.FFTPoly {
	if len(d.buf.fpDcmp) >= gadgetParams.level {
		return d.buf.fpDcmp[:gadgetParams.level]
	}

	oldLen := len(d.buf.fpDcmp)
	d.buf.fpDcmp = append(d.buf.fpDcmp, make([]poly.FFTPoly, gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		d.buf.fpDcmp[i] = d.PolyEvaluator.NewFFTPoly()
	}
	return d.buf.fpDcmp
}

// DecomposeScalar decomposes x with respect to gadgetParams.
func (d *Decomposer[T]) DecomposeScalar(x T, gadgetParams GadgetParameters[T]) []T {
	decomposedOut := make([]T, gadgetParams.level)
	d.DecomposeScalarTo(decomposedOut, x, gadgetParams)
	return decomposedOut
}

// DecomposeScalarTo decomposes x with respect to gadgetParams and writes it to decomposedOut.
func (d *Decomposer[T]) DecomposeScalarTo(decomposedOut []T, x T, gadgetParams GadgetParameters[T]) {
	u := num.DivRoundBits(x, gadgetParams.LogLastBaseQ())
	for i := gadgetParams.level - 1; i >= 1; i-- {
		decomposedOut[i] = u & (gadgetParams.base - 1)
		u >>= gadgetParams.logBase
		u += decomposedOut[i] >> (gadgetParams.logBase - 1)
		decomposedOut[i] -= (decomposedOut[i] & (gadgetParams.base >> 1)) << 1
	}
	decomposedOut[0] = u & (gadgetParams.base - 1)
	decomposedOut[0] -= (decomposedOut[0] & (gadgetParams.base >> 1)) << 1
}

// DecomposePoly decomposes p with respect to gadgetParams.
func (d *Decomposer[T]) DecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	decomposedOut := make([]poly.Poly[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		decomposedOut[i] = poly.NewPoly[T](p.Rank())
	}
	d.DecomposePolyTo(decomposedOut, p, gadgetParams)
	return decomposedOut
}

// DecomposePolyTo decomposes p with respect to gadgetParams and writes it to decomposedOut.
func (d *Decomposer[T]) DecomposePolyTo(decomposedOut []poly.Poly[T], p poly.Poly[T], gadgetParams GadgetParameters[T]) {
	decomposePolyTo(decomposedOut, p, gadgetParams)
}

// FourierDecomposePoly decomposes p with respect to gadgetParams in Fourier domain.
func (d *Decomposer[T]) FourierDecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.FFTPoly {
	decomposedOut := make([]poly.FFTPoly, gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		decomposedOut[i] = d.PolyEvaluator.NewFFTPoly()
	}
	d.FourierDecomposePolyTo(decomposedOut, p, gadgetParams)
	return decomposedOut
}

// FourierDecomposePolyTo decomposes p with respect to gadgetParams in Fourier domain and writes it to decomposedOut.
func (d *Decomposer[T]) FourierDecomposePolyTo(decomposedOut []poly.FFTPoly, p poly.Poly[T], gadgetParams GadgetParameters[T]) {
	pDcmp := d.PolyBuffer(gadgetParams)
	decomposePolyTo(pDcmp, p, gadgetParams)
	for i := 0; i < gadgetParams.level; i++ {
		d.PolyEvaluator.FFTTo(decomposedOut[i], pDcmp[i])
	}
}

// RecomposeScalar recomposes decomposed with respect to gadgetParams.
func (d *Decomposer[T]) RecomposeScalar(decomposed []T, gadgetParams GadgetParameters[T]) T {
	var x T
	for i := 0; i < gadgetParams.level; i++ {
		x += decomposed[i] << gadgetParams.LogBaseQ(i)
	}
	return x
}

// RecomposePoly recomposes decomposed with respect to gadgetParams.
func (d *Decomposer[T]) RecomposePoly(decomposed []poly.Poly[T], gadgetParams GadgetParameters[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](decomposed[0].Rank())
	d.RecomposePolyTo(pOut, decomposed, gadgetParams)
	return pOut
}

// RecomposePolyTo recomposes decomposed with respect to gadgetParams and writes it to pOut.
func (d *Decomposer[T]) RecomposePolyTo(pOut poly.Poly[T], decomposed []poly.Poly[T], gadgetParams GadgetParameters[T]) {
	for i := 0; i < pOut.Rank(); i++ {
		pOut.Coeffs[i] = 0
		for j := 0; j < gadgetParams.level; j++ {
			pOut.Coeffs[i] += decomposed[j].Coeffs[i] << gadgetParams.LogBaseQ(j)
		}
	}
}
