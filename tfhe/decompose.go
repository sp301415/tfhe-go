package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Decompose decomposes x with respect to gadgetParams.
func (e *Evaluator[T]) Decompose(x T, gadgetParams GadgetParameters[T]) []T {
	decomposedOut := make([]T, gadgetParams.level)
	e.DecomposeAssign(x, gadgetParams, decomposedOut)
	return decomposedOut
}

// DecomposeAssign decomposes x with respect to gadgetParams and writes it to decomposedOut.
func (e *Evaluator[T]) DecomposeAssign(x T, gadgetParams GadgetParameters[T], decomposedOut []T) {
	lastScaledBaseLog := gadgetParams.scaledBasesLog[gadgetParams.level-1]
	u := num.RoundRatioBits(x, lastScaledBaseLog)
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
func (e *Evaluator[T]) DecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	decomposedOut := make([]poly.Poly[T], gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		decomposedOut[i] = e.PolyEvaluator.NewPoly()
	}
	e.DecomposePolyAssign(p, gadgetParams, decomposedOut)
	return decomposedOut
}

// DecomposePolyAssign decomposes p with respect to gadgetParams and writes it to decomposedOut.
func (e *Evaluator[T]) DecomposePolyAssign(p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.Poly[T]) {
	decomposePolyAssign(p, gadgetParams, decomposedOut)
}

// FourierDecomposePoly decomposes p with respect to gadgetParams, and transforms it to the Fourier domain.
func (e *Evaluator[T]) FourierDecomposePoly(p poly.Poly[T], gadgetParams GadgetParameters[T]) []poly.FourierPoly {
	decomposedOut := make([]poly.FourierPoly, gadgetParams.level)
	for i := 0; i < gadgetParams.level; i++ {
		decomposedOut[i] = e.FourierEvaluator.NewFourierPoly()
	}
	e.FourierDecomposePolyAssign(p, gadgetParams, decomposedOut)
	return decomposedOut
}

// FourierDecomposePolyAssign decomposes p with respect to gadgetParams,
// transforms it to the Fourier domain,
// and writes it to decomposedOut.
func (e *Evaluator[T]) FourierDecomposePolyAssign(p poly.Poly[T], gadgetParams GadgetParameters[T], decomposedOut []poly.FourierPoly) {
	polyDecomposed := e.polyDecomposedBuffer(gadgetParams)
	decomposePolyAssign(p, gadgetParams, polyDecomposed)

	for i := 0; i < gadgetParams.level; i++ {
		e.FourierEvaluator.ToFourierPolyAssign(polyDecomposed[i], decomposedOut[i])
	}
}

// polyDecomposedBuffer returns the polyDecomposed buffer of Evaluator.
// if len(polyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) polyDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.Poly[T] {
	if len(e.buffer.polyDecomposed) >= gadgetParams.level {
		return e.buffer.polyDecomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.polyDecomposed)
	e.buffer.polyDecomposed = append(e.buffer.polyDecomposed, make([]poly.Poly[T], gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		e.buffer.polyDecomposed[i] = e.PolyEvaluator.NewPoly()
	}
	return e.buffer.polyDecomposed
}

// polyFourierDecomposedBuffer returns the fourierPolyDecomposed buffer of Evaluator.
// if len(fourierPolyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) polyFourierDecomposedBuffer(gadgetParams GadgetParameters[T]) []poly.FourierPoly {
	if len(e.buffer.polyFourierDecomposed) >= gadgetParams.level {
		return e.buffer.polyFourierDecomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.polyFourierDecomposed)
	e.buffer.polyFourierDecomposed = append(e.buffer.polyFourierDecomposed, make([]poly.FourierPoly, gadgetParams.level-oldLen)...)
	for i := oldLen; i < gadgetParams.level; i++ {
		e.buffer.polyFourierDecomposed[i] = e.FourierEvaluator.NewFourierPoly()
	}
	return e.buffer.polyFourierDecomposed
}

// DecomposedBuffer returns the decomposed buffer of Evaluator.
// if len(decomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) DecomposedBuffer(gadgetParams GadgetParameters[T]) []T {
	if len(e.buffer.decomposed) >= gadgetParams.level {
		return e.buffer.decomposed[:gadgetParams.level]
	}

	oldLen := len(e.buffer.decomposed)
	e.buffer.decomposed = append(e.buffer.decomposed, make([]T, gadgetParams.level-oldLen)...)
	return e.buffer.decomposed
}
