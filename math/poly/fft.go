package poly

// FFT returns FFT(p).
func (e *Evaluator[T]) FFT(p Poly[T]) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.FFTTo(fpOut, p)
	return fpOut
}

// FFTTo computes fpOut = FFT(p).
func (e *Evaluator[T]) FFTTo(fpOut FFTPoly, p Poly[T]) {
	foldPolyTo(fpOut.Coeffs, p.Coeffs)
	fftInPlace(fpOut.Coeffs, e.tw)
}

// FFTAddTo computes fpOut += FFT(p).
func (e *Evaluator[T]) FFTAddTo(fpOut FFTPoly, p Poly[T]) {
	foldPolyTo(e.buf.fp.Coeffs, p.Coeffs)
	fftInPlace(e.buf.fp.Coeffs, e.tw)
	addCmplxTo(fpOut.Coeffs, e.buf.fp.Coeffs, fpOut.Coeffs)
}

// FFTSubTo computes fpOut -= FFT(p).
func (e *Evaluator[T]) FFTSubTo(fpOut FFTPoly, p Poly[T]) {
	foldPolyTo(e.buf.fp.Coeffs, p.Coeffs)
	fftInPlace(e.buf.fp.Coeffs, e.tw)
	subCmplxTo(fpOut.Coeffs, e.buf.fp.Coeffs, fpOut.Coeffs)
}

// MonomialFFT returns FFT(X^d).
func (e *Evaluator[T]) MonomialFFT(d int) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.MonomialFFTTo(fpOut, d)
	return fpOut
}

// MonomialFFTTo computes fpOut = FFT(X^d).
func (e *Evaluator[T]) MonomialFFTTo(fpOut FFTPoly, d int) {
	d &= 2*e.rank - 1
	for j, jj := 0, 0; j < e.rank; j, jj = j+8, jj+4 {
		c0 := e.twMono[(e.twMonoIdx[jj+0]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+0] = real(c0)
		fpOut.Coeffs[j+4] = imag(c0)

		c1 := e.twMono[(e.twMonoIdx[jj+1]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+1] = real(c1)
		fpOut.Coeffs[j+5] = imag(c1)

		c2 := e.twMono[(e.twMonoIdx[jj+2]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+2] = real(c2)
		fpOut.Coeffs[j+6] = imag(c2)

		c3 := e.twMono[(e.twMonoIdx[jj+3]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+3] = real(c3)
		fpOut.Coeffs[j+7] = imag(c3)
	}
}

// MonomialSubOneFFT returns FFT(X^d-1).
//
// d should be positive.
func (e *Evaluator[T]) MonomialSubOneFFT(d int) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.MonomialSubOneFFTTo(fpOut, d)
	return fpOut
}

// MonomialSubOneFFTTo computes fpOut = FFT(X^d-1).
//
// d should be positive.
func (e *Evaluator[T]) MonomialSubOneFFTTo(fpOut FFTPoly, d int) {
	d &= 2*e.rank - 1
	for j, jj := 0, 0; j < e.rank; j, jj = j+8, jj+4 {
		c0 := e.twMono[(e.twMonoIdx[jj+0]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+0] = real(c0) - 1
		fpOut.Coeffs[j+4] = imag(c0)

		c1 := e.twMono[(e.twMonoIdx[jj+1]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+1] = real(c1) - 1
		fpOut.Coeffs[j+5] = imag(c1)

		c2 := e.twMono[(e.twMonoIdx[jj+2]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+2] = real(c2) - 1
		fpOut.Coeffs[j+6] = imag(c2)

		c3 := e.twMono[(e.twMonoIdx[jj+3]*d)&(2*e.rank-1)]
		fpOut.Coeffs[j+3] = real(c3) - 1
		fpOut.Coeffs[j+7] = imag(c3)
	}
}

// InvFFT returns InvFFT(fp).
func (e *Evaluator[T]) InvFFT(fp FFTPoly) Poly[T] {
	pOut := NewPoly[T](e.rank)
	e.InvFFTTo(pOut, fp)
	return pOut
}

// InvFFTTo computes pOut = InvFFT(fp).
func (e *Evaluator[T]) InvFFTTo(pOut Poly[T], fp FFTPoly) {
	e.buf.fpInv.CopyFrom(fp)
	ifftInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolyTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTAddTo computes pOut += InvFFT(fp).
func (e *Evaluator[T]) InvFFTAddTo(pOut Poly[T], fp FFTPoly) {
	e.buf.fpInv.CopyFrom(fp)
	ifftInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolyAddTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTSubTo computes pOut -= InvFFT(fp).
func (e *Evaluator[T]) InvFFTSubTo(pOut Poly[T], fp FFTPoly) {
	e.buf.fpInv.CopyFrom(fp)
	ifftInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolySubTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTToUnsafe computes pOut = InvFFT(fp).
//
// This method is slightly faster than [*Evaluator.InvFFTTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTToUnsafe(pOut Poly[T], fp FFTPoly) {
	ifftInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolyTo(pOut.Coeffs, fp.Coeffs)
}

// InvFFTAddToUnsafe computes pOut += InvFFT(fp).
//
// This method is slightly faster than [*Evaluator.InvFFTAddTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTAddToUnsafe(pOut Poly[T], fp FFTPoly) {
	ifftInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolyAddTo(pOut.Coeffs, fp.Coeffs)
}

// InvFFTSubToUnsafe computes pOut -= InvFFT(fp).
//
// This method is slightly faster than [*Evaluator.InvFFTSubTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTSubToUnsafe(pOut Poly[T], fp FFTPoly) {
	ifftInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolySubTo(pOut.Coeffs, fp.Coeffs)
}
