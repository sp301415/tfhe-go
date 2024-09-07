package poly

import "github.com/sp301415/tfhe-go/math/num"

// Mul returns p0 * p1.
func (e *Evaluator[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.MulAssign(p0, p1, pOut)
	return pOut
}

// MulAssign computes pOut = p0 * p1.
func (e *Evaluator[T]) MulAssign(p0, p1, pOut Poly[T]) {
	if e.splitCount == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.ToFourierPolyAssign(p1, e.buffer.fp1Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[0], e.buffer.fpOutSplit[0])
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBits
		for i := 0; i < e.splitCount; i++ {
			var splitLow T = 1 << (i * int(e.splitBits))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	} else {
		var splitMask T = 1<<e.splitBits - 1
		for i := 0; i < e.splitCount; i++ {
			splitLowBits := i * int(e.splitBits)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	}

	for j := 0; j < e.splitCount; j++ {
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[j], e.buffer.fpOutSplit[j])
	}
	for i := 1; i < e.splitCount; i++ {
		for j := 0; j < e.splitCount-i; j++ {
			e.MulAddFourierAssign(e.buffer.fp0Split[i], e.buffer.fp1Split[j], e.buffer.fpOutSplit[i+j])
		}
	}

	e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCount; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBits)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] += e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// MulAddAssign computes pOut += p0 * p1.
func (e *Evaluator[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	if e.splitCount == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.ToFourierPolyAssign(p1, e.buffer.fp1Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[0], e.buffer.fpOutSplit[0])
		e.ToPolyAddAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBits
		for i := 0; i < e.splitCount; i++ {
			var splitLow T = 1 << (i * int(e.splitBits))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	} else {
		var splitMask T = 1<<e.splitBits - 1
		for i := 0; i < e.splitCount; i++ {
			splitLowBits := i * int(e.splitBits)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	}

	for j := 0; j < e.splitCount; j++ {
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[j], e.buffer.fpOutSplit[j])
	}
	for i := 1; i < e.splitCount; i++ {
		for j := 0; j < e.splitCount-i; j++ {
			e.MulAddFourierAssign(e.buffer.fp0Split[i], e.buffer.fp1Split[j], e.buffer.fpOutSplit[i+j])
		}
	}

	e.ToPolyAddAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCount; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBits)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] += e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// MulSubAssign computes pOut -= p0 * p1.
func (e *Evaluator[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	if e.splitCount == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.ToFourierPolyAssign(p1, e.buffer.fp1Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[0], e.buffer.fpOutSplit[0])
		e.ToPolySubAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBits
		for i := 0; i < e.splitCount; i++ {
			var splitLow T = 1 << (i * int(e.splitBits))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	} else {
		var splitMask T = 1<<e.splitBits - 1
		for i := 0; i < e.splitCount; i++ {
			splitLowBits := i * int(e.splitBits)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])

			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp1Split[i])
		}
	}

	for j := 0; j < e.splitCount; j++ {
		e.MulFourierAssign(e.buffer.fp0Split[0], e.buffer.fp1Split[j], e.buffer.fpOutSplit[j])
	}
	for i := 1; i < e.splitCount; i++ {
		for j := 0; j < e.splitCount-i; j++ {
			e.MulAddFourierAssign(e.buffer.fp0Split[i], e.buffer.fp1Split[j], e.buffer.fpOutSplit[i+j])
		}
	}

	e.ToPolySubAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCount; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBits)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] -= e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// BinaryFourierMul returns p0 * bfp, under the assumption that bfp is a binary polynomial.
// This is faster than [*Evaluator.Mul], and the result is exact unlike [*Evaluator.FourierMul].
func (e *Evaluator[T]) BinaryFourierMul(p0 Poly[T], bfp FourierPoly) Poly[T] {
	pOut := e.NewPoly()
	e.BinaryFourierMulAssign(p0, bfp, pOut)
	return pOut
}

// BinaryFourierMulAssign computes pOut = p0 * bfp, under the assumption that bfp is a binary polynomial.
// This is faster than [*Evaluator.MulAssign], and the result is exact unlike [*Evaluator.FourierMulAssign].
func (e *Evaluator[T]) BinaryFourierMulAssign(p0 Poly[T], bfp FourierPoly, pOut Poly[T]) {
	if e.splitCountBinary == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], bfp, e.buffer.fpOutSplit[0])
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBitsBinary
		for i := 0; i < e.splitCountBinary; i++ {
			var splitLow T = 1 << (i * int(e.splitBitsBinary))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	} else {
		var splitMask T = 1<<e.splitBitsBinary - 1
		for i := 0; i < e.splitCountBinary; i++ {
			splitLowBits := i * int(e.splitBitsBinary)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	}

	e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCountBinary; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBitsBinary)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] += e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// BinaryFourierMulAddAssign computes pOut += p0 * bfp, under the assumption that bfp is a binary polynomial.
// This is faster than [*Evaluator.MulAddAssign], and the result is exact unlike [*Evaluator.FourierMulAddAssign].
func (e *Evaluator[T]) BinaryFourierMulAddAssign(p0 Poly[T], bfp FourierPoly, pOut Poly[T]) {
	if e.splitCountBinary == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], bfp, e.buffer.fpOutSplit[0])
		e.ToPolyAddAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBitsBinary
		for i := 0; i < e.splitCountBinary; i++ {
			var splitLow T = 1 << (i * int(e.splitBitsBinary))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	} else {
		var splitMask T = 1<<e.splitBitsBinary - 1
		for i := 0; i < e.splitCountBinary; i++ {
			splitLowBits := i * int(e.splitBitsBinary)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	}

	e.ToPolyAddAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCountBinary; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBitsBinary)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] += e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// BinaryFourierMulSubAssign computes pOut -= p0 * bfp, under the assumption that bfp is a binary polynomial.
// This is faster than [*Evaluator.MulSubAssign], and the result is exact unlike [*Evaluator.FourierMulSubAssign].
func (e *Evaluator[T]) BinaryFourierMulSubAssign(p0 Poly[T], bfp FourierPoly, pOut Poly[T]) {
	if e.splitCountBinary == 1 {
		e.ToFourierPolyAssign(p0, e.buffer.fp0Split[0])
		e.MulFourierAssign(e.buffer.fp0Split[0], bfp, e.buffer.fpOutSplit[0])
		e.ToPolySubAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << e.splitBitsBinary
		for i := 0; i < e.splitCountBinary; i++ {
			var splitLow T = 1 << (i * int(e.splitBitsBinary))
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	} else {
		var splitMask T = 1<<e.splitBitsBinary - 1
		for i := 0; i < e.splitCountBinary; i++ {
			splitLowBits := i * int(e.splitBitsBinary)
			for j := 0; j < e.degree; j++ {
				e.buffer.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.ToFourierPolyAssign(e.buffer.pSplit, e.buffer.fp0Split[i])
			e.MulFourierAssign(e.buffer.fp0Split[i], bfp, e.buffer.fpOutSplit[i])
		}
	}

	e.ToPolySubAssignUnsafe(e.buffer.fpOutSplit[0], pOut)
	for i := 1; i < e.splitCountBinary; i++ {
		e.ToPolyAssignUnsafe(e.buffer.fpOutSplit[i], e.buffer.pSplit)
		splitLowBits := i * int(e.splitBitsBinary)
		for j := 0; j < e.degree; j++ {
			pOut.Coeffs[j] -= e.buffer.pSplit.Coeffs[j] << splitLowBits
		}
	}
}
