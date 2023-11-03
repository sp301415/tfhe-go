package tfhe

import (
	"github.com/sp301415/tfhe-go/math/num"
	"github.com/sp301415/tfhe-go/math/poly"
)

// Decompose decomposes x with respect to decompParams.
func (e *Evaluator[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	decomposedOut := make([]T, decompParams.level)
	e.DecomposeAssign(x, decompParams, decomposedOut)
	return decomposedOut
}

// DecomposeAssign decomposes x with respect to decompParams, and writes it to decomposedOut.
func (e *Evaluator[T]) DecomposeAssign(x T, decompParams DecompositionParameters[T], decomposedOut []T) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	u := num.RoundRatioBits(x, lastScaledBaseLog)
	for i := decompParams.level - 1; i >= 1; i-- {
		decomposedOut[i] = u & decompParams.baseMask
		u >>= decompParams.baseLog
		u += decomposedOut[i] >> decompParams.baseLogMinusOne
		decomposedOut[i] -= (decomposedOut[i] & decompParams.baseHalf) << 1
	}
	decomposedOut[0] = u & decompParams.baseMask
	decomposedOut[0] -= (decomposedOut[0] & decompParams.baseHalf) << 1
}

// DecomposePoly decomposes p with respect to decompParams.
func (e *Evaluator[T]) DecomposePoly(p poly.Poly[T], decompParams DecompositionParameters[T]) []poly.Poly[T] {
	decomposedOut := make([]poly.Poly[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		decomposedOut[i] = e.PolyEvaluator.NewPoly()
	}
	e.DecomposePolyAssign(p, decompParams, decomposedOut)
	return decomposedOut
}

// DecomposePolyAssign decomposes p with respect to decompParams, and writes it to decomposedOut.
func (e *Evaluator[T]) DecomposePolyAssign(p poly.Poly[T], decompParams DecompositionParameters[T], decomposedOut []poly.Poly[T]) {
	decomposePolyAssign(p, decompParams, decomposedOut)
}

// getPolyDecomposedBuffer returns the polyDecomposed buffer of Evaluator.
// if len(polyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) getPolyDecomposedBuffer(decompParams DecompositionParameters[T]) []poly.Poly[T] {
	if len(e.buffer.polyDecomposed) >= decompParams.level {
		return e.buffer.polyDecomposed[:decompParams.level]
	}

	oldLen := len(e.buffer.polyDecomposed)
	e.buffer.polyDecomposed = append(e.buffer.polyDecomposed, make([]poly.Poly[T], decompParams.level-oldLen)...)
	for i := oldLen; i < decompParams.level; i++ {
		e.buffer.polyDecomposed[i] = e.PolyEvaluator.NewPoly()
	}
	return e.buffer.polyDecomposed
}

// getDecomposedBuffer returns the decomposed buffer of Evaluator.
// if len(decomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) getDecomposedBuffer(decompParams DecompositionParameters[T]) []T {
	if len(e.buffer.decomposed) >= decompParams.level {
		return e.buffer.decomposed[:decompParams.level]
	}

	oldLen := len(e.buffer.decomposed)
	e.buffer.decomposed = append(e.buffer.decomposed, make([]T, decompParams.level-oldLen)...)
	return e.buffer.decomposed
}
