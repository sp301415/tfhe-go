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
func (f *FourierEvaluator[T]) PolyMul(p Poly[T], fp0 FourierPoly) FourierPoly {
	fpOut := f.NewFourierPoly()
	f.PolyMulAssign(p, fp0, fpOut)
	return fpOut
}

// PolyMulAssign computes fpOut = p * fp0.
func (f *FourierEvaluator[T]) PolyMulAssign(p Poly[T], fp0, fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign computes fpOut += p * fp0.
func (f *FourierEvaluator[T]) PolyMulAddAssign(p Poly[T], fp0, fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulAddCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign computes fpOut -= p * fp0.
func (f *FourierEvaluator[T]) PolyMulSubAssign(p Poly[T], fp0, fpOut FourierPoly) {
	f.ToFourierPolyAssign(p, f.buffer.fp)

	elementWiseMulSubCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}
