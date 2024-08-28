package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Decomposer decomposes a scalar or a polynomial
// according to the gadget parameters.
//
// Decomposer is safe for concurrent use.
type Decomposer[T TorusInt] struct{}

// NewDecomposer creates a new Decomposer.
func NewDecomposer[T TorusInt]() *Decomposer[T] {
	return &Decomposer[T]{}
}

// Decompose decomposes x with respect to gadgetParams.
func (d *Decomposer[T]) Decompose(x T, gadgetParams GadgetParameters[T]) []T {
	decomposedOut := make([]T, gadgetParams.level)
	d.DecomposeAssign(x, gadgetParams, decomposedOut)
	return decomposedOut
}

// DecomposeAssign decomposes x with respect to gadgetParams and writes it to decomposedOut.
func (d *Decomposer[T]) DecomposeAssign(x T, gadgetParams GadgetParameters[T], decomposedOut []T) {
	lastBaseQLog := gadgetParams.LastBaseQLog()
	u := num.DivRoundBits(x, lastBaseQLog)
	for i := gadgetParams.level - 1; i >= 1; i-- {
		decomposedOut[i] = u & (gadgetParams.base - 1)
		u >>= gadgetParams.baseLog
		u += decomposedOut[i] >> (gadgetParams.baseLog - 1)
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

// Recompose recomposes decomposed with respect to gadgetParams.
func (d *Decomposer[T]) Recompose(decomposed []T, gadgetParams GadgetParameters[T]) T {
	var x T
	for i := 0; i < gadgetParams.level; i++ {
		x <<= gadgetParams.baseLog
		x += decomposed[i]
	}
	return x << gadgetParams.LastBaseQLog()
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
			pOut.Coeffs[i] <<= gadgetParams.baseLog
			pOut.Coeffs[i] += decomposed[j].Coeffs[i]
		}
		pOut.Coeffs[i] <<= gadgetParams.LastBaseQLog()
	}
}
