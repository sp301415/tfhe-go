package poly

import "unsafe"

// FwdFFT returns FwdFFT(p).
func (e *Evaluator[T]) FwdFFT(p Poly[T]) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.FwdFFTTo(fpOut, p)
	return fpOut
}

// FwdFFTTo computes fpOut = FFT(p).
func (e *Evaluator[T]) FwdFFTTo(fpOut FFTPoly, p Poly[T]) {
	checkLength(e.rank, len(fpOut.Coeffs), len(p.Coeffs))

	foldPolyTo(fpOut.Coeffs, p.Coeffs)
	fwdFFTInPlace(fpOut.Coeffs, e.tw)
}

// FwdFFTAddTo computes fpOut += FFT(p).
func (e *Evaluator[T]) FwdFFTAddTo(fpOut FFTPoly, p Poly[T]) {
	checkLength(e.rank, len(fpOut.Coeffs), len(p.Coeffs))

	foldPolyTo(e.buf.fp.Coeffs, p.Coeffs)
	fwdFFTInPlace(e.buf.fp.Coeffs, e.tw)
	addCmplxTo(fpOut.Coeffs, e.buf.fp.Coeffs, fpOut.Coeffs)
}

// FwdFFTSubTo computes fpOut -= FFT(p).
func (e *Evaluator[T]) FwdFFTSubTo(fpOut FFTPoly, p Poly[T]) {
	checkLength(e.rank, len(fpOut.Coeffs), len(p.Coeffs))

	foldPolyTo(e.buf.fp.Coeffs, p.Coeffs)
	fwdFFTInPlace(e.buf.fp.Coeffs, e.tw)
	subCmplxTo(fpOut.Coeffs, e.buf.fp.Coeffs, fpOut.Coeffs)
}

// MonomialFwdFFT returns FFT(X^d).
func (e *Evaluator[T]) MonomialFwdFFT(d int) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.MonomialFwdFFTTo(fpOut, d)
	return fpOut
}

// MonomialFwdFFTTo computes fpOut = FFT(X^d).
func (e *Evaluator[T]) MonomialFwdFFTTo(fpOut FFTPoly, d int) {
	checkLength(e.rank, len(fpOut.Coeffs))

	LI := unsafe.Sizeof(int(0))
	LC := unsafe.Sizeof(complex128(0))
	LF := unsafe.Sizeof(float64(0))

	rIdx := unsafe.Pointer(&e.twMonoIdx[:1][0])
	r := unsafe.Pointer(&e.twMono[:1][0])
	v := unsafe.Pointer(&fpOut.Coeffs[:1][0])

	d &= 2*e.rank - 1
	for j, jj := 0, 0; j < e.rank; j, jj = j+8, jj+4 {
		ii := (*[4]int)(unsafe.Add(rIdx, uintptr(jj)*LI))
		w := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))

		c0 := *(*complex128)(unsafe.Add(r, uintptr((ii[0]*d)&(2*e.rank-1))*LC))
		c1 := *(*complex128)(unsafe.Add(r, uintptr((ii[1]*d)&(2*e.rank-1))*LC))
		c2 := *(*complex128)(unsafe.Add(r, uintptr((ii[2]*d)&(2*e.rank-1))*LC))
		c3 := *(*complex128)(unsafe.Add(r, uintptr((ii[3]*d)&(2*e.rank-1))*LC))

		w[0] = real(c0)
		w[4] = imag(c0)

		w[1] = real(c1)
		w[5] = imag(c1)

		w[2] = real(c2)
		w[6] = imag(c2)

		w[3] = real(c3)
		w[7] = imag(c3)
	}
}

// MonomialSubOneFwdFFT returns FFT(X^d-1).
//
// d should be positive.
func (e *Evaluator[T]) MonomialSubOneFwdFFT(d int) FFTPoly {
	fpOut := NewFFTPoly(e.rank)
	e.MonomialSubOneFwdFFTTo(fpOut, d)
	return fpOut
}

// MonomialSubOneFwdFFTTo computes fpOut = FFT(X^d-1).
//
// d should be positive.
func (e *Evaluator[T]) MonomialSubOneFwdFFTTo(fpOut FFTPoly, d int) {
	checkLength(e.rank, len(fpOut.Coeffs))

	LI := unsafe.Sizeof(int(0))
	LC := unsafe.Sizeof(complex128(0))
	LF := unsafe.Sizeof(float64(0))

	rIdx := unsafe.Pointer(&e.twMonoIdx[:1][0])
	r := unsafe.Pointer(&e.twMono[:1][0])
	v := unsafe.Pointer(&fpOut.Coeffs[:1][0])

	d &= 2*e.rank - 1
	for j, jj := 0, 0; j < e.rank; j, jj = j+8, jj+4 {
		ii := (*[4]int)(unsafe.Add(rIdx, uintptr(jj)*LI))
		w := (*[8]float64)(unsafe.Add(v, uintptr(j)*LF))

		c0 := *(*complex128)(unsafe.Add(r, uintptr((ii[0]*d)&(2*e.rank-1))*LC))
		c1 := *(*complex128)(unsafe.Add(r, uintptr((ii[1]*d)&(2*e.rank-1))*LC))
		c2 := *(*complex128)(unsafe.Add(r, uintptr((ii[2]*d)&(2*e.rank-1))*LC))
		c3 := *(*complex128)(unsafe.Add(r, uintptr((ii[3]*d)&(2*e.rank-1))*LC))

		w[0] = real(c0) - 1
		w[4] = imag(c0)

		w[1] = real(c1) - 1
		w[5] = imag(c1)

		w[2] = real(c2) - 1
		w[6] = imag(c2)

		w[3] = real(c3) - 1
		w[7] = imag(c3)
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
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	e.buf.fpInv.CopyFrom(fp)
	invFFTInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolyTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTAddTo computes pOut += InvFFT(fp).
func (e *Evaluator[T]) InvFFTAddTo(pOut Poly[T], fp FFTPoly) {
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	e.buf.fpInv.CopyFrom(fp)
	invFFTInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolyAddTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTSubTo computes pOut -= InvFFT(fp).
func (e *Evaluator[T]) InvFFTSubTo(pOut Poly[T], fp FFTPoly) {
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	e.buf.fpInv.CopyFrom(fp)
	invFFTInPlace(e.buf.fpInv.Coeffs, e.twInv)
	floatModQInPlace(e.buf.fpInv.Coeffs, e.q)
	unfoldPolySubTo(pOut.Coeffs, e.buf.fpInv.Coeffs)
}

// InvFFTToUnsafe computes pOut = InvFFT(fp).
//
// This method is slightly faster than [Evaluator.InvFFTTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTToUnsafe(pOut Poly[T], fp FFTPoly) {
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	invFFTInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolyTo(pOut.Coeffs, fp.Coeffs)
}

// InvFFTAddToUnsafe computes pOut += InvFFT(fp).
//
// This method is slightly faster than [Evaluator.InvFFTAddTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTAddToUnsafe(pOut Poly[T], fp FFTPoly) {
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	invFFTInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolyAddTo(pOut.Coeffs, fp.Coeffs)
}

// InvFFTSubToUnsafe computes pOut -= InvFFT(fp).
//
// This method is slightly faster than [Evaluator.InvFFTSubTo], but it modifies fp directly.
// Use it only if you don't need fp after this method (e.g. fp is a buffer).
func (e *Evaluator[T]) InvFFTSubToUnsafe(pOut Poly[T], fp FFTPoly) {
	checkLength(e.rank, len(fp.Coeffs), len(pOut.Coeffs))

	invFFTInPlace(fp.Coeffs, e.twInv)
	floatModQInPlace(fp.Coeffs, e.q)
	unfoldPolySubTo(pOut.Coeffs, fp.Coeffs)
}
