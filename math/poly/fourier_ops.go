package poly

// AddFourierPoly returns fp0 + fp1.
func (e *Evaluator[T]) AddFourierPoly(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.AddFourierPolyAssign(fp0, fp1, fpOut)
	return fpOut
}

// AddFourierPolyAssign computes fpOut = fp0 + fp1.
func (e *Evaluator[T]) AddFourierPolyAssign(fp0, fp1, fpOut FourierPoly) {
	addCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// SubFourierPoly returns fp0 - fp1.
func (e *Evaluator[T]) SubFourierPoly(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.SubFourierPolyAssign(fp0, fp1, fpOut)
	return fpOut
}

// SubFourierPolyAssign computes fpOut = fp0 - fp1.
func (e *Evaluator[T]) SubFourierPolyAssign(fp0, fp1, fpOut FourierPoly) {
	subCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// NegFourierPoly returns -fp0.
func (e *Evaluator[T]) NegFourierPoly(fp0 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.NegFourierPolyAssign(fp0, fpOut)
	return fpOut
}

// NegFourierPolyAssign computes fpOut = -fp0.
func (e *Evaluator[T]) NegFourierPolyAssign(fp0, fpOut FourierPoly) {
	negCmplxAssign(fp0.Coeffs, fpOut.Coeffs)
}

// FloatMulFourierPoly returns c * fp0.
func (e *Evaluator[T]) FloatMulFourierPoly(fp0 FourierPoly, c float64) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.FloatMulFourierPolyAssign(fp0, c, fpOut)
	return fpOut
}

// FloatMulFourierPolyAssign computes fpOut = c * fp0.
func (e *Evaluator[T]) FloatMulFourierPolyAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulAddFourierPolyAssign computes fpOut += c * fp0.
func (e *Evaluator[T]) FloatMulAddFourierPolyAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulSubFourierPolyAssign computes fpOut -= c * fp0.
func (e *Evaluator[T]) FloatMulSubFourierPolyAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulFourierPoly returns c * fp0.
func (e *Evaluator[T]) CmplxMulFourierPoly(fp0 FourierPoly, c complex128) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.CmplxMulFourierPolyAssign(fp0, c, fpOut)
	return fpOut
}

// CmplxMulFourierPolyAssign computes fpOut = c * fp0.
func (e *Evaluator[T]) CmplxMulFourierPolyAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulAddFourierPolyAssign computes fpOut += c * fp0.
func (e *Evaluator[T]) CmplxMulAddFourierPolyAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulSubFourierPolyAssign computes fpOut -= c * fp0.
func (e *Evaluator[T]) CmplxMulSubFourierPolyAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// MulFourierPoly returns fp0 * fp1.
func (e *Evaluator[T]) MulFourierPoly(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.MulFourierPolyAssign(fp0, fp1, fpOut)
	return fpOut
}

// MulFourierPolyAssign computes fpOut = fp0 * fp1.
func (e *Evaluator[T]) MulFourierPolyAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddFourierPolyAssign computes fpOut += fp0 * fp1.
func (e *Evaluator[T]) MulAddFourierPolyAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulAddCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubFourierPolyAssign computes fpOut -= fp0 * fp1.
func (e *Evaluator[T]) MulSubFourierPolyAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulSubCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMulFourierPoly returns p * fp0 as FourierPoly.
func (e *Evaluator[T]) PolyMulFourierPoly(fp0 FourierPoly, p Poly[T]) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.PolyMulFourierPolyAssign(fp0, p, fpOut)
	return fpOut
}

// PolyMulFourierPolyAssign computes fpOut = p * fp0.
func (e *Evaluator[T]) PolyMulFourierPolyAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fp)

	elementWiseMulCmplxAssign(fp0.Coeffs, e.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddFourierPolyAssign computes fpOut += p * fp0.
func (e *Evaluator[T]) PolyMulAddFourierPolyAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fp)

	elementWiseMulAddCmplxAssign(fp0.Coeffs, e.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubFourierPolyAssign computes fpOut -= p * fp0.
func (e *Evaluator[T]) PolyMulSubFourierPolyAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fp)

	elementWiseMulSubCmplxAssign(fp0.Coeffs, e.buffer.fp.Coeffs, fpOut.Coeffs)
}
