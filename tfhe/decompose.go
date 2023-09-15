package tfhe

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/poly"
)

// Decompose decomposes x with respect to decompParams.
func (e *Evaluator[T]) Decompose(x T, decompParams DecompositionParameters[T]) []T {
	decomposed := make([]T, decompParams.level)
	e.DecomposeAssign(x, decomposed, decompParams)
	return decomposed
}

// DecomposeAssign decomposes x with respect to decompParams, and writes it to d.
func (e *Evaluator[T]) DecomposeAssign(x T, d []T, decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	u := num.RoundRatioBits(x, lastScaledBaseLog)
	for i := decompParams.level - 1; i >= 1; i-- {
		d[i] = u & decompParams.baseMask
		u >>= decompParams.baseLog
		u += d[i] >> (decompParams.baseLog - 1)
		d[i] -= (d[i] & decompParams.baseHalf) << 1
	}
	d[0] = u & decompParams.baseMask
	d[0] -= (d[0] & decompParams.baseHalf) << 1
}

// DecomposePoly decomposes x with respect to decompParams.
func (e *Evaluator[T]) DecomposePoly(x poly.Poly[T], decompParams DecompositionParameters[T]) []poly.Poly[T] {
	decomposed := make([]poly.Poly[T], decompParams.level)
	for i := 0; i < decompParams.level; i++ {
		decomposed[i] = poly.New[T](e.Parameters.polyDegree)
	}
	e.DecomposePolyAssign(x, decomposed, decompParams)
	return decomposed
}

// DecomposePolyAssign decomposes x with respect to decompParams, and writes it to d.
func (e *Evaluator[T]) DecomposePolyAssign(x poly.Poly[T], d []poly.Poly[T], decompParams DecompositionParameters[T]) {
	lastScaledBaseLog := decompParams.scaledBasesLog[decompParams.level-1]
	for i := 0; i < e.Parameters.polyDegree; i++ {
		c := num.RoundRatioBits(x.Coeffs[i], lastScaledBaseLog)
		for j := decompParams.level - 1; j >= 1; j-- {
			d[j].Coeffs[i] = c & decompParams.baseMask
			c >>= decompParams.baseLog
			c += d[j].Coeffs[i] >> (decompParams.baseLog - 1)
			d[j].Coeffs[i] -= (d[j].Coeffs[i] & decompParams.baseHalf) << 1
		}
		d[0].Coeffs[i] = c & decompParams.baseMask
		d[0].Coeffs[i] -= (d[0].Coeffs[i] & decompParams.baseHalf) << 1
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
