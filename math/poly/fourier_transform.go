package poly

// ToFourierPoly transforms Poly to FourierPoly and returns it.
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

	twistInPlace(fpOut.Coeffs, f.w2Nj)
	fftInPlace(fpOut.Coeffs, f.wNj)
}

// ToScaledFourierPoly transforms Poly to FourierPoly and returns it.
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

	twistAndScaleInPlace(fp.Coeffs, f.w2Nj, 1/f.maxT)
	fftInPlace(fp.Coeffs, f.wNj)
}

// ToStandardPoly transforms FourierPoly to Poly and returns it.
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
	unTwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToStandardPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
func (f *FourierEvaluator[T]) ToStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
func (f *FourierEvaluator[T]) ToStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly and returns it.
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
	unTwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] = T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] = -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] += T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] += -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAndScaleInPlace(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT)

	for j := 0; j < N/2; j++ {
		pOut.Coeffs[j] -= T(int64(real(f.buffer.fpInv.Coeffs[j])))
		pOut.Coeffs[j+N/2] -= -T(int64(imag(f.buffer.fpInv.Coeffs[j])))
	}
}
