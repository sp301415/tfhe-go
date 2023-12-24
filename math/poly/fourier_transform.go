package poly

// ToFourierPoly transforms Poly to FourierPoly, and returns it.
func (f *FourierEvaluator[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fp)
	return fp
}

// ToFourierPolyAssign transforms Poly to FourierPoly, and writes it to fpOut.
func (f *FourierEvaluator[T]) ToFourierPolyAssign(p Poly[T], fpOut FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(int(p.Coeffs[j])), float64(int(-p.Coeffs[j+N/2])))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(int8(p.Coeffs[j])), float64(int8(-p.Coeffs[j+N/2])))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(int16(p.Coeffs[j])), float64(int16(-p.Coeffs[j+N/2])))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(int32(p.Coeffs[j])), float64(int32(-p.Coeffs[j+N/2])))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(int64(p.Coeffs[j])), float64(int64(-p.Coeffs[j+N/2])))
		}
	default:
		for j := 0; j < N/2; j++ {
			fpOut.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(-p.Coeffs[j+N/2]))
		}
	}

	elementWiseMulCmplxAssign(fpOut.Coeffs, f.w2Nj, fpOut.Coeffs)
	fftInPlace(fpOut.Coeffs, f.wNj)
}

// MonomialToFourierPoly transforms X^d to FourierPoly, and returns it.
//
// Assumes d is positive.
func (f *FourierEvaluator[T]) MonomialToFourierPoly(d int) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MonomialToFourierPolyAssign(d, fp)
	return fp
}

// MonomialToFourierPolyAssign transforms X^d to FourierPoly, and writes it to fpOut.
//
// Assumes d is positive.
func (f *FourierEvaluator[T]) MonomialToFourierPolyAssign(d int, fpOut FourierPoly) {
	for j := 0; j < f.degree/2; j++ {
		fpOut.Coeffs[j] = f.w2NjMono[(f.revOddIdx[j]*d)&(2*f.degree-1)]
	}
}

// ToScaledFourierPoly transforms Poly to FourierPoly, and returns it.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyAssign(p, fp)
	return fp
}

// ToScaledFourierPolyAssign transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledFourierPolyAssign(p Poly[T], fp FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int(p.Coeffs[j])), float64(int(-p.Coeffs[j+N/2])))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int8(p.Coeffs[j])), float64(int8(-p.Coeffs[j+N/2])))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int16(p.Coeffs[j])), float64(int16(-p.Coeffs[j+N/2])))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int32(p.Coeffs[j])), float64(int32(-p.Coeffs[j+N/2])))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(int64(p.Coeffs[j])), float64(int64(-p.Coeffs[j+N/2])))
		}
	default:
		for j := 0; j < N/2; j++ {
			fp.Coeffs[j] = complex(float64(p.Coeffs[j]), float64(-p.Coeffs[j+N/2]))
		}
	}

	elementWiseMulCmplxAssign(fp.Coeffs, f.w2NjScaled, fp.Coeffs)
	fftInPlace(fp.Coeffs, f.wNj)
}

// ToStandardPoly transforms FourierPoly to Poly, and returns it.
func (f *FourierEvaluator[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToStandardPolyAssign(fp, p)
	return p
}

// ToStandardPolyAssign transforms FourierPoly to Poly, and writes it to pOut.
func (f *FourierEvaluator[T]) ToStandardPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToStandardPolyAssignUnsafe transforms FourierPoly to Poly, and writes it to pOut.
//
// This method is slightly faster than ToStandardPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistInPlace(fp.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(fp.Coeffs[j])))
	}
}

// ToStandardPolyAddAssign transforms FourierPoly to Poly, and adds it to pOut.
func (f *FourierEvaluator[T]) ToStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToStandardPolyAddAssignUnsafe transforms FourierPoly to Poly, and adds it to pOut.
//
// This method is slightly faster than ToStandardPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistInPlace(fp.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(fp.Coeffs[j])))
	}
}

// ToStandardPolySubAssign transforms FourierPoly to Poly, and subtracts it from pOut.
func (f *FourierEvaluator[T]) ToStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToStandardPolySubAssignUnsafe transforms FourierPoly to Poly, and subtracts it from pOut.
//
// This method is slightly faster than ToStandardPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistInPlace(fp.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(fp.Coeffs[j])))
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly, and returns it.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, p)
	return p
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly, and writes it to pOut.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPolyAssignUnsafe transforms FourierPoly to Poly, and writes it to pOut.
// Each coefficients are scaled by 2^sizeT.
//
// This method is slightly faster than ToScaledStandardPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(fp.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(fp.Coeffs[j])))
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly, and adds it to pOut.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPolyAddAssignUnsafe transforms FourierPoly to Poly, and adds it to pOut.
// Each coefficients are scaled by 2^sizeT.
//
// This method is slightly faster than ToScaledStandardPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(fp.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(fp.Coeffs[j])))
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly, and subtracts it from pOut.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPolySubAssignUnsafe transforms FourierPoly to Poly, and subtracts it from pOut.
// Each coefficients are scaled by 2^sizeT.
//
// This method is slightly faster than ToScaledStandardPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	untwistAndScaleInPlace(fp.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(fp.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(fp.Coeffs[j])))
	}
}
