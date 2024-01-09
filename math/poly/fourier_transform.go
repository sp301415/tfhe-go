package poly

// ToFourierPoly transforms Poly to FourierPoly.
func (f *FourierEvaluator[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fpOut := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fpOut)
	return fpOut
}

// ToFourierPolyAssign transforms Poly to FourierPoly and writes it to fpOut.
func (f *FourierEvaluator[T]) ToFourierPolyAssign(p Poly[T], fpOut FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int(p.Coeffs[jj+3+N/2]))
		}
	case uint8:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int8(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int8(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int8(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int8(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int8(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int8(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int8(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int8(p.Coeffs[jj+3+N/2]))
		}
	case uint16:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int16(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int16(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int16(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int16(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int16(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int16(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int16(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int16(p.Coeffs[jj+3+N/2]))
		}
	case uint32:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int32(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int32(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int32(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int32(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int32(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int32(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int32(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int32(p.Coeffs[jj+3+N/2]))
		}
	case uint64:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int64(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int64(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int64(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int64(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int64(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int64(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int64(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int64(p.Coeffs[jj+3+N/2]))
		}
	default:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(p.Coeffs[jj+0])
			fpOut.Coeffs[j+1] = float64(p.Coeffs[jj+1])
			fpOut.Coeffs[j+2] = float64(p.Coeffs[jj+2])
			fpOut.Coeffs[j+3] = float64(p.Coeffs[jj+3])

			fpOut.Coeffs[j+4] = float64(p.Coeffs[jj+0+N/2])
			fpOut.Coeffs[j+5] = float64(p.Coeffs[jj+1+N/2])
			fpOut.Coeffs[j+6] = float64(p.Coeffs[jj+2+N/2])
			fpOut.Coeffs[j+7] = float64(p.Coeffs[jj+3+N/2])
		}
	}

	fftInPlace(fpOut.Coeffs, f.wNj)
}

// MonomialToFourierPoly transforms X^d to FourierPoly.
//
// d should be positive.
func (f *FourierEvaluator[T]) MonomialToFourierPoly(d int) FourierPoly {
	fpOut := NewFourierPoly(f.degree)
	f.MonomialToFourierPolyAssign(d, fpOut)
	return fpOut
}

// MonomialToFourierPolyAssign transforms X^d to FourierPoly and writes it to fpOut.
//
// d should be positive.
func (f *FourierEvaluator[T]) MonomialToFourierPolyAssign(d int, fpOut FourierPoly) {
	for j, jj := 0, 0; j < f.degree; j, jj = j+8, jj+4 {
		c0 := f.w4NjMono[(f.revMonoIdx[jj+0]*d)&((f.degree<<1)-1)]
		fpOut.Coeffs[j+0] = real(c0)
		fpOut.Coeffs[j+4] = imag(c0)

		c1 := f.w4NjMono[(f.revMonoIdx[jj+1]*d)&((f.degree<<1)-1)]
		fpOut.Coeffs[j+1] = real(c1)
		fpOut.Coeffs[j+5] = imag(c1)

		c2 := f.w4NjMono[(f.revMonoIdx[jj+2]*d)&((f.degree<<1)-1)]
		fpOut.Coeffs[j+2] = real(c2)
		fpOut.Coeffs[j+6] = imag(c2)

		c3 := f.w4NjMono[(f.revMonoIdx[jj+3]*d)&((f.degree<<1)-1)]
		fpOut.Coeffs[j+3] = real(c3)
		fpOut.Coeffs[j+7] = imag(c3)
	}
}

// ToScaledFourierPoly transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / MaxT.
func (f *FourierEvaluator[T]) ToScaledFourierPoly(p Poly[T]) FourierPoly {
	fpOut := NewFourierPoly(f.degree)
	f.ToScaledFourierPolyAssign(p, fpOut)
	return fpOut
}

// ToScaledFourierPolyAssign transforms Poly to FourierPoly.
// Each coefficients are scaled by 1 / MaxT.
func (f *FourierEvaluator[T]) ToScaledFourierPolyAssign(p Poly[T], fpOut FourierPoly) {
	N := f.degree

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int(p.Coeffs[jj+3+N/2]))
		}
	case uint8:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int8(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int8(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int8(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int8(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int8(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int8(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int8(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int8(p.Coeffs[jj+3+N/2]))
		}
	case uint16:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int16(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int16(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int16(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int16(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int16(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int16(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int16(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int16(p.Coeffs[jj+3+N/2]))
		}
	case uint32:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int32(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int32(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int32(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int32(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int32(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int32(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int32(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int32(p.Coeffs[jj+3+N/2]))
		}
	case uint64:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(int64(p.Coeffs[jj+0]))
			fpOut.Coeffs[j+1] = float64(int64(p.Coeffs[jj+1]))
			fpOut.Coeffs[j+2] = float64(int64(p.Coeffs[jj+2]))
			fpOut.Coeffs[j+3] = float64(int64(p.Coeffs[jj+3]))

			fpOut.Coeffs[j+4] = float64(int64(p.Coeffs[jj+0+N/2]))
			fpOut.Coeffs[j+5] = float64(int64(p.Coeffs[jj+1+N/2]))
			fpOut.Coeffs[j+6] = float64(int64(p.Coeffs[jj+2+N/2]))
			fpOut.Coeffs[j+7] = float64(int64(p.Coeffs[jj+3+N/2]))
		}
	default:
		for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
			fpOut.Coeffs[j+0] = float64(p.Coeffs[jj+0])
			fpOut.Coeffs[j+1] = float64(p.Coeffs[jj+1])
			fpOut.Coeffs[j+2] = float64(p.Coeffs[jj+2])
			fpOut.Coeffs[j+3] = float64(p.Coeffs[jj+3])

			fpOut.Coeffs[j+4] = float64(p.Coeffs[jj+0+N/2])
			fpOut.Coeffs[j+5] = float64(p.Coeffs[jj+1+N/2])
			fpOut.Coeffs[j+6] = float64(p.Coeffs[jj+2+N/2])
			fpOut.Coeffs[j+7] = float64(p.Coeffs[jj+3+N/2])
		}
	}

	floatMulCmplxAssign(1/f.maxT, fpOut.Coeffs, fpOut.Coeffs)
	fftInPlace(fpOut.Coeffs, f.wNj)
}

// ToStandardPoly transforms FourierPoly to Poly.
func (f *FourierEvaluator[T]) ToStandardPoly(fp FourierPoly) Poly[T] {
	pOut := NewPoly[T](f.degree)
	f.ToStandardPolyAssign(fp, pOut)
	return pOut
}

// ToStandardPolyAssign transforms FourierPoly to Poly and writes it to pOut.
func (f *FourierEvaluator[T]) ToStandardPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	roundCmplxAssign(f.buffer.fpInv.Coeffs, f.buffer.fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] = T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] = T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] = T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] = T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToStandardPolyAssignUnsafe transforms FourierPoly to Poly and writes it to pOut.
//
// This method is slightly faster than ToStandardPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	roundCmplxAssign(fp.Coeffs, fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] = T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] = T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] = T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] = T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] = T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] = T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] = T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] = T(int64(fp.Coeffs[j+7]))
	}
}

// ToStandardPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
func (f *FourierEvaluator[T]) ToStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	roundCmplxAssign(f.buffer.fpInv.Coeffs, f.buffer.fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] += T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] += T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] += T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] += T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToStandardPolyAddAssignUnsafe transforms FourierPoly to Poly and adds it to pOut.
//
// This method is slightly faster than ToStandardPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	roundCmplxAssign(fp.Coeffs, fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] += T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] += T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] += T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] += T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] += T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] += T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] += T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] += T(int64(fp.Coeffs[j+7]))
	}
}

// ToStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
func (f *FourierEvaluator[T]) ToStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	roundCmplxAssign(f.buffer.fpInv.Coeffs, f.buffer.fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] -= T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] -= T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] -= T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] -= T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToStandardPolySubAssignUnsafe transforms FourierPoly to Poly and subtracts it from pOut.
//
// This method is slightly faster than ToStandardPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToStandardPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	roundCmplxAssign(fp.Coeffs, fp.Coeffs)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] -= T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] -= T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] -= T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] -= T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] -= T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] -= T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] -= T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] -= T(int64(fp.Coeffs[j+7]))
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	pOut := NewPoly[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, pOut)
	return pOut
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly and writes it to pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	scaleMaxTInPlace(f.buffer.fpInv.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] = T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] = T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] = T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] = T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] = T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToScaledStandardPolyAssignUnsafe transforms FourierPoly to Poly and writes it to pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledStandardPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	scaleMaxTInPlace(fp.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] = T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] = T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] = T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] = T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] = T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] = T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] = T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] = T(int64(fp.Coeffs[j+7]))
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	scaleMaxTInPlace(f.buffer.fpInv.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] += T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] += T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] += T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] += T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] += T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToScaledStandardPolyAddAssignUnsafe transforms FourierPoly to Poly and adds it to pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledStandardPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	scaleMaxTInPlace(fp.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] += T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] += T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] += T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] += T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] += T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] += T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] += T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] += T(int64(fp.Coeffs[j+7]))
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	scaleMaxTInPlace(f.buffer.fpInv.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] -= T(int64(f.buffer.fpInv.Coeffs[j+0]))
		pOut.Coeffs[jj+1] -= T(int64(f.buffer.fpInv.Coeffs[j+1]))
		pOut.Coeffs[jj+2] -= T(int64(f.buffer.fpInv.Coeffs[j+2]))
		pOut.Coeffs[jj+3] -= T(int64(f.buffer.fpInv.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] -= T(int64(f.buffer.fpInv.Coeffs[j+7]))
	}
}

// ToScaledStandardPolySubAssignUnsafe transforms FourierPoly to Poly and subtracts it from pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledStandardPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.wNjInv)
	scaleMaxTInPlace(fp.Coeffs, f.maxT)

	for j, jj := 0, 0; j < N; j, jj = j+8, jj+4 {
		pOut.Coeffs[jj+0] -= T(int64(fp.Coeffs[j+0]))
		pOut.Coeffs[jj+1] -= T(int64(fp.Coeffs[j+1]))
		pOut.Coeffs[jj+2] -= T(int64(fp.Coeffs[j+2]))
		pOut.Coeffs[jj+3] -= T(int64(fp.Coeffs[j+3]))

		pOut.Coeffs[jj+0+N/2] -= T(int64(fp.Coeffs[j+4]))
		pOut.Coeffs[jj+1+N/2] -= T(int64(fp.Coeffs[j+5]))
		pOut.Coeffs[jj+2+N/2] -= T(int64(fp.Coeffs[j+6]))
		pOut.Coeffs[jj+3+N/2] -= T(int64(fp.Coeffs[j+7]))
	}
}
