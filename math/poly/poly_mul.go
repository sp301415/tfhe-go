package poly

import "github.com/sp301415/tfhe-go/math/num"

// MulPoly returns p0 * p1.
func (e *Evaluator[T]) MulPoly(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.MulPolyTo(pOut, p0, p1)
	return pOut
}

// MulPolyTo computes pOut = p0 * p1.
func (e *Evaluator[T]) MulPolyTo(pOut, p0, p1 Poly[T]) {
	checkConsistentPoly(e.rank, pOut, p0, p1)

	splitBits, splitCount := splitParameters[T](e.rank)

	if splitCount == 1 {
		fp0 := e.FwdFFTPoly(p0)
		fp1 := e.FwdFFTPoly(p1)
		e.MulFFTPolyTo(fp0, fp0, fp1)
		e.InvFFTToUnsafe(pOut, fp0)
		return
	}

	fp0Split := make([]FFTPoly, splitCount)
	fp1Split := make([]FFTPoly, splitCount)
	fpOutSplit := make([]FFTPoly, splitCount)
	for i := 0; i < splitCount; i++ {
		fp0Split[i] = e.NewFFTPoly()
		fp1Split[i] = e.NewFFTPoly()
		fpOutSplit[i] = e.NewFFTPoly()
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	}

	for i := 0; i < splitCount; i++ {
		for j := 0; j < splitCount-i; j++ {
			e.MulAddFFTPolyTo(fpOutSplit[i+j], fp0Split[i], fp1Split[j])
		}
	}

	e.InvFFTToUnsafe(pOut, fpOutSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, fpOutSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] += e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// MulAddPolyTo computes pOut += p0 * p1.
func (e *Evaluator[T]) MulAddPolyTo(pOut, p0, p1 Poly[T]) {
	checkConsistentPoly(e.rank, pOut, p0, p1)

	splitBits, splitCount := splitParameters[T](e.rank)

	if splitCount == 1 {
		fp0 := e.FwdFFTPoly(p0)
		fp1 := e.FwdFFTPoly(p1)
		e.MulFFTPolyTo(fp0, fp0, fp1)
		e.InvFFTAddToUnsafe(pOut, fp0)
		return
	}

	fp0Split := make([]FFTPoly, splitCount)
	fp1Split := make([]FFTPoly, splitCount)
	fpOutSplit := make([]FFTPoly, splitCount)
	for i := 0; i < splitCount; i++ {
		fp0Split[i] = e.NewFFTPoly()
		fp1Split[i] = e.NewFFTPoly()
		fpOutSplit[i] = e.NewFFTPoly()
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	}

	for i := 0; i < splitCount; i++ {
		for j := 0; j < splitCount-i; j++ {
			e.MulAddFFTPolyTo(fpOutSplit[i+j], fp0Split[i], fp1Split[j])
		}
	}

	e.InvFFTAddToUnsafe(pOut, fpOutSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, fpOutSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] += e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// MulSubPolyTo computes pOut -= p0 * p1.
func (e *Evaluator[T]) MulSubPolyTo(pOut, p0, p1 Poly[T]) {
	checkConsistentPoly(e.rank, pOut, p0, p1)

	splitBits, splitCount := splitParameters[T](e.rank)

	if splitCount == 1 {
		fp0 := e.FwdFFTPoly(p0)
		fp1 := e.FwdFFTPoly(p1)
		e.MulFFTPolyTo(fp0, fp0, fp1)
		e.InvFFTAddToUnsafe(pOut, fp0)
		return
	}

	fp0Split := make([]FFTPoly, splitCount)
	fp1Split := make([]FFTPoly, splitCount)
	fpOutSplit := make([]FFTPoly, splitCount)
	for i := 0; i < splitCount; i++ {
		fp0Split[i] = e.NewFFTPoly()
		fp1Split[i] = e.NewFFTPoly()
		fpOutSplit[i] = e.NewFFTPoly()
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p0.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp0Split[i], e.buf.pSplit)

			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p1.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(fp1Split[i], e.buf.pSplit)
		}
	}

	for i := 0; i < splitCount; i++ {
		for j := 0; j < splitCount-i; j++ {
			e.MulAddFFTPolyTo(fpOutSplit[i+j], fp0Split[i], fp1Split[j])
		}
	}

	e.InvFFTSubToUnsafe(pOut, fpOutSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, fpOutSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] -= e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// ShortFFTPolyMulPoly returns fpShort * p, under the assumption that fpShort is a short polynomial.
// (i.e., all coefficients are bounded by [ShortLogBound] bits.)
// This is faster than [*Evaluator.MulPoly], and the result is exact unlike [*Evaluator.FFTPolyMulPoly].
func (e *Evaluator[T]) ShortFFTPolyMulPoly(p Poly[T], fpShort FFTPoly) Poly[T] {
	pOut := e.NewPoly()
	e.ShortFFTPolyMulPolyTo(pOut, p, fpShort)
	return pOut
}

// ShortFFTPolyMulPolyTo computes pOut = fpShort * p, under the assumption that fpShort is a short polynomial.
// (i.e., all coefficients are bounded by [ShortLogBound] bits.)
// This is faster than [*Evaluator.MulPolyTo], and the result is exact unlike [*Evaluator.FFTPolyMulPolyTo].
func (e *Evaluator[T]) ShortFFTPolyMulPolyTo(pOut, p Poly[T], fpShort FFTPoly) {
	checkConsistentPoly(e.rank, pOut, p)
	checkConsistentFFTPoly(e.rank, fpShort)

	splitBits, splitCount := splitParamsShort[T](e.rank)

	if splitCount == 1 {
		e.FwdFFTPolyTo(e.buf.fpSplit[0], p)
		e.MulFFTPolyTo(e.buf.fpSplit[0], e.buf.fpSplit[0], fpShort)
		e.InvFFTToUnsafe(pOut, e.buf.fpSplit[0])
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	}

	e.InvFFTToUnsafe(pOut, e.buf.fpSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, e.buf.fpSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] += e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// ShortFFTPolyMulAddPolyTo computes pOut += fpShort * p, under the assumption that fpShort is a short polynomial.
// (i.e., all coefficients are bounded by [ShortLogBound] bits.)
// This is faster than [*Evaluator.MulAddPolyTo], and the result is exact unlike [*Evaluator.FFTPolyMulAddPolyTo].
func (e *Evaluator[T]) ShortFFTPolyMulAddPolyTo(pOut, p Poly[T], fpShort FFTPoly) {
	checkConsistentPoly(e.rank, pOut, p)
	checkConsistentFFTPoly(e.rank, fpShort)

	splitBits, splitCount := splitParamsShort[T](e.rank)

	if splitCount == 1 {
		e.FwdFFTPolyTo(e.buf.fpSplit[0], p)
		e.MulFFTPolyTo(e.buf.fpSplit[0], e.buf.fpSplit[0], fpShort)
		e.InvFFTAddToUnsafe(pOut, e.buf.fpSplit[0])
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	}

	e.InvFFTAddToUnsafe(pOut, e.buf.fpSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, e.buf.fpSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] += e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}

// ShortFFTPolyMulSubPolyTo computes pOut -= fpShort * p, under the assumption that fpShort is a short polynomial.
// (i.e., all coefficients are bounded by [ShortLogBound] bits.)
// This is faster than [*Evaluator.MulSubPolyTo], and the result is exact unlike [*Evaluator.FFTPolyMulSubPolyTo].
func (e *Evaluator[T]) ShortFFTPolyMulSubPolyTo(pOut, p Poly[T], fpShort FFTPoly) {
	checkConsistentPoly(e.rank, pOut, p)
	checkConsistentFFTPoly(e.rank, fpShort)

	splitBits, splitCount := splitParamsShort[T](e.rank)

	if splitCount == 1 {
		e.FwdFFTPolyTo(e.buf.fpSplit[0], p)
		e.MulFFTPolyTo(e.buf.fpSplit[0], e.buf.fpSplit[0], fpShort)
		e.InvFFTSubToUnsafe(pOut, e.buf.fpSplit[0])
		return
	}

	if num.IsSigned[T]() {
		var splitChunk T = 1 << splitBits
		for i := 0; i < splitCount; i++ {
			var splitLow T = 1 << (i * int(splitBits))
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] / splitLow) % splitChunk
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	} else {
		var splitMask T = 1<<splitBits - 1
		for i := 0; i < splitCount; i++ {
			splitLowBits := i * int(splitBits)
			for j := 0; j < e.rank; j++ {
				e.buf.pSplit.Coeffs[j] = (p.Coeffs[j] >> splitLowBits) & splitMask
			}
			e.FwdFFTPolyTo(e.buf.fpSplit[i], e.buf.pSplit)
			e.MulFFTPolyTo(e.buf.fpSplit[i], e.buf.fpSplit[i], fpShort)
		}
	}

	e.InvFFTSubToUnsafe(pOut, e.buf.fpSplit[0])
	for i := 1; i < splitCount; i++ {
		e.InvFFTToUnsafe(e.buf.pSplit, e.buf.fpSplit[i])
		splitLowBits := i * int(splitBits)
		for j := 0; j < e.rank; j++ {
			pOut.Coeffs[j] -= e.buf.pSplit.Coeffs[j] << splitLowBits
		}
	}
}
