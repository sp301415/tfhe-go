package poly

// ToFourierPoly transforms Poly to FourierPoly.
func (f *FourierEvaluator[T]) ToFourierPoly(p Poly[T]) FourierPoly {
	fpOut := NewFourierPoly(f.degree)
	f.ToFourierPolyAssign(p, fpOut)
	return fpOut
}

// ToFourierPolyAssign transforms Poly to FourierPoly and writes it to fpOut.
func (f *FourierEvaluator[T]) ToFourierPolyAssign(p Poly[T], fpOut FourierPoly) {
	convertPolyToFourierPolyAssign(p.Coeffs, fpOut.Coeffs)
	fftInPlace(fpOut.Coeffs, f.tw)
}

// ToFourierPolyAddAssign transforms Poly to FourierPoly and adds it to fpOut.
func (f *FourierEvaluator[T]) ToFourierPolyAddAssign(p Poly[T], fpOut FourierPoly) {
	convertPolyToFourierPolyAssign(p.Coeffs, f.buffer.fp.Coeffs)
	fftInPlace(f.buffer.fp.Coeffs, f.tw)
	addCmplxAssign(fpOut.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// ToFourierPolySubAssign transforms Poly to FourierPoly and subtracts it from fpOut.
func (f *FourierEvaluator[T]) ToFourierPolySubAssign(p Poly[T], fpOut FourierPoly) {
	convertPolyToFourierPolyAssign(p.Coeffs, f.buffer.fp.Coeffs)
	fftInPlace(f.buffer.fp.Coeffs, f.tw)
	subCmplxAssign(fpOut.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
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
func (f *FourierEvaluator[T]) MonomialToFourierPolyAssign(d int, fpOut FourierPoly) {
	d &= 2*f.degree - 1
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

// MonomialSubOneToFourierPoly transforms X^d-1 to FourierPoly.
//
// d should be positive.
func (f *FourierEvaluator[T]) MonomialSubOneToFourierPoly(d int) FourierPoly {
	fpOut := NewFourierPoly(f.degree)
	f.MonomialSubOneToFourierPolyAssign(d, fpOut)
	return fpOut
}

// MonomialSubOneToFourierPolyAssign transforms X^d-1 to FourierPoly and writes it to fpOut.
func (f *FourierEvaluator[T]) MonomialSubOneToFourierPolyAssign(d int, fpOut FourierPoly) {
	d &= 2*f.degree - 1
	for j, jj := 0, 0; j < f.degree; j, jj = j+8, jj+4 {
		c0 := f.twMono[(f.twMonoIdx[jj+0]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+0] = real(c0) - 1
		fpOut.Coeffs[j+4] = imag(c0)

		c1 := f.twMono[(f.twMonoIdx[jj+1]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+1] = real(c1) - 1
		fpOut.Coeffs[j+5] = imag(c1)

		c2 := f.twMono[(f.twMonoIdx[jj+2]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+2] = real(c2) - 1
		fpOut.Coeffs[j+6] = imag(c2)

		c3 := f.twMono[(f.twMonoIdx[jj+3]*d)&(2*f.degree-1)]
		fpOut.Coeffs[j+3] = real(c3) - 1
		fpOut.Coeffs[j+7] = imag(c3)
	}
}

// ToPoly transforms FourierPoly to Poly.
func (f *FourierEvaluator[T]) ToPoly(fp FourierPoly) Poly[T] {
	pOut := NewPoly[T](f.degree)
	f.ToPolyAssign(fp, pOut)
	return pOut
}

// ToPolyAssign transforms FourierPoly to Poly and writes it to pOut.
func (f *FourierEvaluator[T]) ToPolyAssign(fp FourierPoly, pOut Poly[T]) {
	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
	floatModQInPlace(f.buffer.fpInv.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolyAssign(f.buffer.fpInv.Coeffs, pOut.Coeffs)
}

// ToPolyAddAssign transforms FourierPoly to Poly and adds it to pOut.
func (f *FourierEvaluator[T]) ToPolyAddAssign(fp FourierPoly, pOut Poly[T]) {
	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
	floatModQInPlace(f.buffer.fpInv.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolyAddAssign(f.buffer.fpInv.Coeffs, pOut.Coeffs)
}

// ToPolySubAssign transforms FourierPoly to Poly and subtracts it from pOut.
func (f *FourierEvaluator[T]) ToPolySubAssign(fp FourierPoly, pOut Poly[T]) {
	f.buffer.fpInv.CopyFrom(fp)
	invFFTInPlace(f.buffer.fpInv.Coeffs, f.twInv)
	floatModQInPlace(f.buffer.fpInv.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolySubAssign(f.buffer.fpInv.Coeffs, pOut.Coeffs)
}

// ToPolyAssignUnsafe transforms FourierPoly to Poly and writes it to pOut.
//
// This method is slightly faster than ToPolyAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolyAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	invFFTInPlace(fp.Coeffs, f.twInv)
	floatModQInPlace(fp.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolyAssign(fp.Coeffs, pOut.Coeffs)
}

// ToPolyAddAssignUnsafe transforms FourierPoly to Poly and adds it to pOut.
//
// This method is slightly faster than ToPolyAddAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolyAddAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	invFFTInPlace(fp.Coeffs, f.twInv)
	floatModQInPlace(fp.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolyAddAssign(fp.Coeffs, pOut.Coeffs)
}

// ToPolySubAssignUnsafe transforms FourierPoly to Poly and subtracts it from pOut.
//
// This method is slightly faster than ToPolySubAssign, but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (f *FourierEvaluator[T]) ToPolySubAssignUnsafe(fp FourierPoly, pOut Poly[T]) {
	invFFTInPlace(fp.Coeffs, f.twInv)
	floatModQInPlace(fp.Coeffs, f.q, f.qInv)
	convertFourierPolyToPolySubAssign(fp.Coeffs, pOut.Coeffs)
}
