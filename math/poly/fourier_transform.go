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

	fftInPlace(fpOut.Coeffs, f.tw)
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
		c0 := f.twMono[(f.twMonoIdx[jj+0]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+0] = real(c0)
		fpOut.Coeffs[j+4] = imag(c0)

		c1 := f.twMono[(f.twMonoIdx[jj+1]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+1] = real(c1)
		fpOut.Coeffs[j+5] = imag(c1)

		c2 := f.twMono[(f.twMonoIdx[jj+2]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+2] = real(c2)
		fpOut.Coeffs[j+6] = imag(c2)

		c3 := f.twMono[(f.twMonoIdx[jj+3]*d)&(2*f.degree-1)]
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

	floatMulCmplxAssign(fpOut.Coeffs, 1/f.maxT, fpOut.Coeffs)
	fftInPlace(fpOut.Coeffs, f.tw)
}

// ToPoly transforms FourierPoly to Poly.
func (f *FourierEvaluator[T]) ToPoly(fp FourierPoly) Poly[T] {
	pOut := NewPoly[T](f.degree)
	f.ToPolyAssign(fp, pOut)
	return pOut
}

// ToPolyAssign transforms FourierPoly to Poly and writes it to pOut.
func (f *FourierEvaluator[T]) ToPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToPolyAssignUnsafe transforms FourierPoly to Poly and writes it to pOut.
//
// This method is slightly faster than ToPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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

// ToPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
func (f *FourierEvaluator[T]) ToPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToPolyAddAssignUnsafe transforms FourierPoly to Poly and adds it to pOut.
//
// This method is slightly faster than ToPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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

// ToPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
func (f *FourierEvaluator[T]) ToPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToPolySubAssignUnsafe transforms FourierPoly to Poly and subtracts it from pOut.
//
// This method is slightly faster than ToPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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

// ToScaledPoly transforms FourierPoly to Poly.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledPoly(fp FourierPoly) Poly[T] {
	pOut := NewPoly[T](f.degree)
	f.ToScaledPolyAssign(fp, pOut)
	return pOut
}

// ToScaledPolyAssign transforms FourierPoly to Poly and writes it to pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledPolyAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToScaledPolyAssignUnsafe transforms FourierPoly to Poly and writes it to pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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

// ToScaledPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToScaledPolyAddAssignUnsafe transforms FourierPoly to Poly and adds it to pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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

// ToScaledPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
// Each coefficients are scaled by MaxT.
func (f *FourierEvaluator[T]) ToScaledPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
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

// ToScaledPolySubAssignUnsafe transforms FourierPoly to Poly and subtracts it from pOut.
// Each coefficients are scaled by MaxT.
//
// This method is slightly faster than ToScaledPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToScaledPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	invFFTInPlace(fp.Coeffs, f.twInv)
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
