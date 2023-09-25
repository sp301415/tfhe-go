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
		decomposedOut[i] = poly.New[T](e.Parameters.polyDegree)
	}
	e.DecomposePolyAssign(p, decompParams, decomposedOut)
	return decomposedOut
}

// DecomposePolyAssign decomposes p with respect to decompParams, and writes it to decompOut.
func (e *Evaluator[T]) DecomposePolyAssign(p poly.Poly[T], decompParams DecompositionParameters[T], decomposedOut []poly.Poly[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	for i := 0; i < e.Parameters.polyDegree; i++ {
		c := num.RoundRatioBits(p.Coeffs[i], lastScaledBaseLog)
		for j := decompParams.level - 1; j >= 1; j-- {
			decomposedOut[j].Coeffs[i] = c & decompParams.baseMask
			c >>= decompParams.baseLog
			c += decomposedOut[j].Coeffs[i] >> decompParams.baseLogMinusOne
			decomposedOut[j].Coeffs[i] -= (decomposedOut[j].Coeffs[i] & decompParams.baseHalf) << 1
		}
		decomposedOut[0].Coeffs[i] = c & decompParams.baseMask
		decomposedOut[0].Coeffs[i] -= (decomposedOut[0].Coeffs[i] & decompParams.baseHalf) << 1
	}
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
		e.buffer.polyDecomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}
	return e.buffer.polyDecomposed
}

// getVecDecomposedBuffer returns the vecDecomposed buffer of Evaluator.
// if len(vecDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) getVecDecomposedBuffer(decompParams DecompositionParameters[T]) []T {
	if len(e.buffer.vecDecomposed) >= decompParams.level {
		return e.buffer.vecDecomposed[:decompParams.level]
	}

	oldLen := len(e.buffer.vecDecomposed)
	e.buffer.vecDecomposed = append(e.buffer.vecDecomposed, make([]T, decompParams.level-oldLen)...)
	return e.buffer.vecDecomposed
}
