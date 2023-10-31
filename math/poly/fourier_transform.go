package poly

// FFTInPlace applies FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierEvaluator[T]) FFTInPlace(fp FourierPoly) {
	fftInPlace(fp.Coeffs, f.wNj)
}

// InvFFTInPlace applies Inverse FFT to fp.
//
// Note that fp.Degree() should equal f.Degree(),
// which means that len(fp.Coeffs) should be f.Degree / 2.
func (f *FourierEvaluator[T]) InvFFTInPlace(fp FourierPoly) {
	invFFTInPlace(fp.Coeffs, f.wNjInv)
}

// ToFourierPoly transforms Poly to FourierPoly and returns it.
func (f *FourierEvaluator[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fp)
	return fp
}

// ToFourierPolyAssign transforms Poly to FourierPoly.
func (f *FourierEvaluator[T]) ToFourierPolyAssign(p Poly[T], fp FourierPoly) {
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

	twistInPlace(fp.Coeffs, f.w2Nj)
	fftInPlace(fp.Coeffs, f.wNj)
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

// ToStandardPolyAssign transforms FourierPoly to Poly.
func (f *FourierEvaluator[T]) ToStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] = -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}

// ToStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
func (f *FourierEvaluator[T]) ToStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] += -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}

// ToStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
func (f *FourierEvaluator[T]) ToStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] -= -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}

// ToScaledStandardPoly transforms FourierPoly to Poly and returns it.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPoly(fp FourierPoly) Poly[T] {
	p := New[T](f.degree)
	f.ToScaledStandardPolyAssign(fp, p)
	return p
}

// ToScaledStandardPolyAssign transforms FourierPoly to Poly.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAndScaleAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] = -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] = T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] = -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}

// ToScaledStandardPolyAddAssign transforms FourierPoly to Poly and adds it to p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolyAddAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAndScaleAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] += -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] += T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] += -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}

// ToScaledStandardPolySubAssign transforms FourierPoly to Poly and subtracts it from p.
// Each coefficients are scaled by 2^sizeT.
func (f *FourierEvaluator[T]) ToScaledStandardPolySubAssign(fp FourierPoly, p Poly[T]) {
	N := f.degree

	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.wNjInv)
	unTwistAndScaleAssign(f.buffer.fpInv.Coeffs, f.w2NjInv, f.maxT, f.buffer.floatCoeffs)

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint8:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int8(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int8(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint16:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int16(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int16(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint32:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int32(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int32(f.buffer.floatCoeffs[2*j+1]))
		}
	case uint64:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(int64(f.buffer.floatCoeffs[2*j]))
			p.Coeffs[j+N/2] -= -T(int64(f.buffer.floatCoeffs[2*j+1]))
		}
	default:
		for j := 0; j < N/2; j++ {
			p.Coeffs[j] -= T(f.buffer.floatCoeffs[2*j])
			p.Coeffs[j+N/2] -= -T(f.buffer.floatCoeffs[2*j+1])
		}
	}
}
