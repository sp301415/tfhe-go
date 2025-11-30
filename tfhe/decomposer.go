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
	dcmpOut := make([]T, gadgetParams.level)
	d.DecomposeScalarTo(dcmpOut, x, gadgetParams)
	return dcmpOut
}

// DecomposeScalarTo decomposes x with respect to gadgetParams and writes it to dcmpOut.
func (d *Decomposer[T]) DecomposeScalarTo(dcmpOut []T, x T, gadgetParams GadgetParameters[T]) {
	u := num.DivRoundBits(x, gadgetParams.LogLastBaseQ())
	for i := gadgetParams.level - 1; i >= 1; i-- {
		dcmpOut[i] = u & (gadgetParams.base - 1)
		u >>= gadgetParams.logBase
		u += dcmpOut[i] >> (gadgetParams.logBase - 1)
		dcmpOut[i] -= (dcmpOut[i] & (gadgetParams.base >> 1)) << 1
	}
	dcmpOut[0] = u & (gadgetParams.base - 1)
	dcmpOut[0] -= (dcmpOut[0] & (gadgetParams.base >> 1)) << 1
}

// DecomposePoly decomposes p with respect to gadgetParams.
func (d *Decomposer[T]) DecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	dcmpOut := make([]poly.Poly[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		dcmpOut[i] = poly.NewPoly[T](p.Rank())
	}
	d.DecomposePolyTo(dcmpOut, p, gadgetParams)
	return dcmpOut
}

// DecomposePolyTo decomposes p with respect to gadgetParams and writes it to dcmpOut.
func (d *Decomposer[T]) DecomposePolyTo(dcmpOut []poly.Poly[T], p poly.Poly[T], gadgetParams GadgetParameters[T]) {
	decomposePolyTo(dcmpOut, p, gadgetParams)
}

// FourierDecomposePoly decomposes p with respect to gadgetParams in Fourier domain.
func (d *Decomposer[T]) FourierDecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.FFTPoly {
	dcmpOut := make([]poly.FFTPoly, gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		dcmpOut[i] = d.PolyEvaluator.NewFFTPoly()
	}
	d.FourierDecomposePolyTo(dcmpOut, p, gadgetParams)
	return dcmpOut
}

// FourierDecomposePolyTo decomposes p with respect to gadgetParams in Fourier domain and writes it to dcmpOut.
func (d *Decomposer[T]) FourierDecomposePolyTo(dcmpOut []poly.FFTPoly, p poly.Poly[T], gadgetParams GadgetParameters[T]) {
	pDcmp := d.PolyBuffer(gadgetParams)
	decomposePolyTo(pDcmp, p, gadgetParams)
	for i := 0; i < gadgetParams.level; i++ {
		d.PolyEvaluator.FwdFFTPolyTo(dcmpOut[i], pDcmp[i])
	}
}

// RecomposeScalar recomposes decomposed with respect to gadgetParams.
func (d *Decomposer[T]) RecomposeScalar(dcmp []T, gadgetParams GadgetParameters[T]) T {
	var x T
	for i := 0; i < gadgetParams.level; i++ {
		x += dcmp[i] << gadgetParams.LogBaseQ(i)
	}
	return x
}

// RecomposePoly recomposes decomposed with respect to gadgetParams.
func (d *Decomposer[T]) RecomposePoly(dcmp []poly.Poly[T], gadgetParams GadgetParameters[T]) poly.Poly[T] {
	pOut := poly.NewPoly[T](dcmp[0].Rank())
	d.RecomposePolyTo(pOut, dcmp, gadgetParams)
	return pOut
}

// RecomposePolyTo recomposes decomposed with respect to gadgetParams and writes it to pOut.
func (d *Decomposer[T]) RecomposePolyTo(pOut poly.Poly[T], dcmp []poly.Poly[T], gadgetParams GadgetParameters[T]) {
	for i := 0; i < pOut.Rank(); i++ {
		pOut.Coeffs[i] = 0
		for j := 0; j < gadgetParams.level; j++ {
			pOut.Coeffs[i] += dcmp[j].Coeffs[i] << gadgetParams.LogBaseQ(j)
		}
	}
}
