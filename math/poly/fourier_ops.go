package poly

// Add adds fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fp := f.NewFourierPoly()
	f.AddAssign(fp0, fp1, fp)
	return fp
}

// AddAssign adds fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) AddAssign(fp0, fp1, fpOut FourierPoly) {
	addCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Sub subtracts fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fp := f.NewFourierPoly()
	f.SubAssign(fp0, fp1, fp)
	return fp
}

// SubAssign subtracts fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) SubAssign(fp0, fp1, fpOut FourierPoly) {
	subCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Neg negates fp0 and returns the result.
func (f *FourierEvaluator[T]) Neg(fp0 FourierPoly) FourierPoly {
	fp := f.NewFourierPoly()
	f.NegAssign(fp0, fp)
	return fp
}

// NegAssign negates fp0 and writes it to fpOut.
func (f *FourierEvaluator[T]) NegAssign(fp0, fpOut FourierPoly) {
	negCmplxAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Mul multiplies fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fp := f.NewFourierPoly()
	f.MulAssign(fp0, fp1, fp)
	return fp
}

// MulAssign multiplies fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) MulAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddAssign multiplies fp0, fp1 and adds it to fpOut.
func (f *FourierEvaluator[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulAddCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f *FourierEvaluator[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulSubCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMul multiplies fp0, p1 and returns the result.
func (f *FourierEvaluator[T]) PolyMul(fp0 FourierPoly, p1 Poly[T]) FourierPoly {
	fp := f.NewFourierPoly()
	f.PolyMulAssign(fp0, p1, fp)
	return fp
}

// PolyMulAssign multiplies fp0, p1 and writes it to fpOut.
func (f *FourierEvaluator[T]) PolyMulAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	elementWiseMulCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f *FourierEvaluator[T]) PolyMulAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	elementWiseMulAddCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign multiplies fp0, p1 and subtracts it from fpOut.
func (f *FourierEvaluator[T]) PolyMulSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	elementWiseMulSubCmplxAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}
