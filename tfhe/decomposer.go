package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Decomposer decomposes a scalar or a polynomial
// according to the gadget parameters.
//
// Decomposer is not safe for concurrent use.
// Use [*Decomposer.ShallowCopy] to get a safe copy.
type Decomposer[T TorusInt] struct {
	// PolyEvaluator is a PolyEvaluator for this Decomposer.
	PolyEvaluator *poly.Evaluator[T]

	buffer decompositionBuffer[T]
}

// decompositionBuffer is a buffer for Decomposer.
type decompositionBuffer[T TorusInt] struct {
	// scalarDecomposed is the scalarDecomposed scalar.
	scalarDecomposed []T
	// polyDecomposed is the decomposed polynomial.
	polyDecomposed []poly.Poly[T]
	// polyFourierDecomposed is the decomposed polynomial in Fourier domain.
	polyFourierDecomposed []poly.FourierPoly
}

// NewDecomposer creates a new Decomposer.
func NewDecomposer[T TorusInt](N int) *Decomposer[T] {
	return &Decomposer[T]{
		PolyEvaluator: poly.NewEvaluator[T](N),

		buffer: decompositionBuffer[T]{},
	}
}

// ShallowCopy returns a shallow copy of this Decomposer.
// Returned Decomposer is safe for concurrent use.
func (d *Decomposer[T]) ShallowCopy() *Decomposer[T] {
	decompositionBufferCopy := decompositionBuffer[T]{
		scalarDecomposed:      make([]T, len(d.buffer.scalarDecomposed)),
		polyDecomposed:        make([]poly.Poly[T], len(d.buffer.polyDecomposed)),
		polyFourierDecomposed: make([]poly.FourierPoly, len(d.buffer.polyFourierDecomposed)),
	}

	for i := range decompositionBufferCopy.polyDecomposed {
		decompositionBufferCopy.polyDecomposed[i] = d.PolyEvaluator.NewPoly()
	}
	for i := range decompositionBufferCopy.polyFourierDecomposed {
		decompositionBufferCopy.polyFourierDecomposed[i] = d.PolyEvaluator.NewFourierPoly()
	}

	return &Decomposer[T]{
		PolyEvaluator: d.PolyEvaluator.ShallowCopy(),

		buffer: decompositionBufferCopy,
	}
}

// ScalarDecomposedBuffer returns a internal buffer for scalar decomposition with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) ScalarDecomposedBuffer(gadgetParams GadgetParameters[T]) []T {
	if len(d.buffer.scalarDecomposed) >= gadgetParams.level {
		return d.buffer.scalarDecomposed[:gadgetParams.level]
	}

	oldLen := len(d.buffer.scalarDecomposed)
	d.buffer.scalarDecomposed = append(d.buffer.scalarDecomposed, make([]T, gadgetParams.level-oldLen)...)
	return d.buffer.scalarDecomposed
}

// PolyDecomposedBuffer returns a internal buffer for polynomial decomposition with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) PolyDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	if len(d.buffer.polyDecomposed) >= gadgetParams.level {
		return d.buffer.polyDecomposed[:gadgetParams.level]
	}

	oldLen := len(d.buffer.polyDecomposed)
	d.buffer.polyDecomposed = append(d.buffer.polyDecomposed, make([]poly.Poly[T], gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		d.buffer.polyDecomposed[i] = d.PolyEvaluator.NewPoly()
	}
	return d.buffer.polyDecomposed
}

// PolyFourierDecomposedBuffer returns a internal buffer for polynomial decomposition in Fourier domain with respect to gadgetParams.
//
// You can also set the length of the internal buffer by calling this function and ignoring the return value.
func (d *Decomposer[T]) PolyFourierDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.FourierPoly {
	if len(d.buffer.polyFourierDecomposed) >= gadgetParams.level {
		return d.buffer.polyFourierDecomposed[:gadgetParams.level]
	}

	oldLen := len(d.buffer.polyFourierDecomposed)
	d.buffer.polyFourierDecomposed = append(d.buffer.polyFourierDecomposed, make([]poly.FourierPoly, gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		d.buffer.polyFourierDecomposed[i] = d.PolyEvaluator.NewFourierPoly()
	}
	return d.buffer.polyFourierDecomposed
}

// DecomposeScalar decomposes x with respect to gadgetParams.
func (d *Decomposer[T]) DecomposeScalar(x T, gadgetParams GadgetParameters[T]) []T {
	decomposedOut := make([]T, gadgetParams.level)
	d.DecomposeScalarAssign(x, gadgetParams, decomposedOut)
	return decomposedOut
}

// DecomposeScalarAssign decomposes x with respect to gadgetParams and writes it to decomposedOut.
func (d *Decomposer[T]) DecomposeScalarAssign(x T, gadgetParams GadgetParameters[T], decomposedOut []T) {
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
		decomposedOut[i] = poly.NewPoly[T](p.Degree())
	}
	d.DecomposePolyAssign(p, gadgetParams, decomposedOut)
	return decomposedOut
}

// DecomposePolyAssign decomposes p with respect to gadgetParams and writes it to decomposedOut.
func (d *Decomposer[T]) DecomposePolyAssign(p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.Poly[T]) {
	decomposePolyAssign(p, gadgetParams, decomposedOut)
}

// FourierDecomposePoly decomposes p with respect to gadgetParams in Fourier domain.
func (d *Decomposer[T]) FourierDecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.FourierPoly {
	decomposedOut := make([]poly.FourierPoly, gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		decomposedOut[i] = d.PolyEvaluator.NewFourierPoly()
	}
	d.FourierDecomposePolyAssign(p, gadgetParams, decomposedOut)
	return decomposedOut
}

// FourierDecomposePolyAssign decomposes p with respect to gadgetParams in Fourier domain and writes it to decomposedOut.
func (d *Decomposer[T]) FourierDecomposePolyAssign(p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.FourierPoly) {
	polyDecomposed := d.PolyDecomposedBuffer(gadgetParams)
	decomposePolyAssign(p, gadgetParams, polyDecomposed)
	for i := 0; i < gadgetParams.level; i++ {
		d.PolyEvaluator.ToFourierPolyAssign(polyDecomposed[i], decomposedOut[i])
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
	pOut := poly.NewPoly[T](decomposed[0].Degree())
	d.RecomposePolyAssign(decomposed, gadgetParams, pOut)
	return pOut
}

// RecomposePolyAssign recomposes decomposed with respect to gadgetParams and writes it to pOut.
func (d *Decomposer[T]) RecomposePolyAssign(decomposed []poly.Poly[T], gadgetParams GadgetParameters[T], pOut poly.Poly[T]) {
	for i := 0; i < pOut.Degree(); i++ {
		pOut.Coeffs[i] = 0
		for j := 0; j < gadgetParams.level; j++ {
			pOut.Coeffs[i] += decomposed[j].Coeffs[i] << gadgetParams.LogBaseQ(j)
		}
	}
}
