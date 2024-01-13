package poly

// Add returns fp0 + fp1.
func (f *FourierEvaluator[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.AddAssign(fp0, fp1, fpOut)
	return fpOut
}

// AddAssign computes fpOut = fp0 + fp1.
func (f *FourierEvaluator[T]) AddAssign(fp0, fp1, fpOut FourierPoly) {
	addCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Sub returns fp0 - fp1.
func (f *FourierEvaluator[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.SubAssign(fp0, fp1, fpOut)
	return fpOut
}

// SubAssign computes fpOut = fp0 - fp1.
func (f *FourierEvaluator[T]) SubAssign(fp0, fp1, fpOut FourierPoly) {
	subCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Neg returns -fp0.
func (f *FourierEvaluator[T]) Neg(fp0 FourierPoly) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.NegAssign(fp0, fpOut)
	return fpOut
}

// NegAssign computes fpOut = -fp0.
func (f *FourierEvaluator[T]) NegAssign(fp0, fpOut FourierPoly) {
	negCmplxAssign(fp0.Coeffs, fpOut.Coeffs)
}

// FloatMul returns c * fp0.
func (f *FourierEvaluator[T]) FloatMul(fp0 FourierPoly, c float64) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.FloatMulAssign(fp0, c, fpOut)
	return fpOut
}

// FloatMulAssign computes fpOut = c * fp0.
func (f *FourierEvaluator[T]) FloatMulAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulAddAssign computes fpOut += c * fp0.
func (f *FourierEvaluator[T]) FloatMulAddAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulSubAssign computes fpOut -= c * fp0.
func (f *FourierEvaluator[T]) FloatMulSubAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMul returns c * fp0.
func (f *FourierEvaluator[T]) CmplxMul(fp0 FourierPoly, c complex128) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.CmplxMulAssign(fp0, c, fpOut)
	return fpOut
}

// CmplxMulAssign computes fpOut = c * fp0.
func (f *FourierEvaluator[T]) CmplxMulAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulAddAssign computes fpOut += c * fp0.
func (f *FourierEvaluator[T]) CmplxMulAddAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulSubAssign computes fpOut -= c * fp0.
func (f *FourierEvaluator[T]) CmplxMulSubAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// Mul returns fp0 * fp1.
func (f *FourierEvaluator[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.MulAssign(fp0, fp1, fpOut)
	return fpOut
}

// MulAssign computes fpOut = fp0 * fp1.
func (f *FourierEvaluator[T]) MulAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddAssign computes fpOut += fp0 * fp1.
func (f *FourierEvaluator[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulAddCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign computes fpOut -= fp0 * fp1.
func (f *FourierEvaluator[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulSubCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMul returns p * fp0 as FourierPoly.
func (f *FourierEvaluator[T]) PolyMul(fp0 FourierPoly, p Poly[T]) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.PolyMulAssign(fp0, p, fpOut)
	return fpOut
}

// PolyMulAssign computes fpOut = p * fp0.
func (f *FourierEvaluator[T]) PolyMulAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign computes fpOut += p * fp0.
func (f *FourierEvaluator[T]) PolyMulAddAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulAddCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign computes fpOut -= p * fp0.
func (f *FourierEvaluator[T]) PolyMulSubAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulSubCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}
