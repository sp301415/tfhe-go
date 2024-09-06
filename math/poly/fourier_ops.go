package poly

// AddFourier returns fp0 + fp1.
func (e *Evaluator[T]) AddFourier(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.AddFourierAssign(fp0, fp1, fpOut)
	return fpOut
}

// AddFourierAssign computes fpOut = fp0 + fp1.
func (e *Evaluator[T]) AddFourierAssign(fp0, fp1, fpOut FourierPoly) {
	addCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// SubFourier returns fp0 - fp1.
func (e *Evaluator[T]) SubFourier(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.SubFourierAssign(fp0, fp1, fpOut)
	return fpOut
}

// SubFourierAssign computes fpOut = fp0 - fp1.
func (e *Evaluator[T]) SubFourierAssign(fp0, fp1, fpOut FourierPoly) {
	subCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// NegFourier returns -fp0.
func (e *Evaluator[T]) NegFourier(fp0 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.NegFourierAssign(fp0, fpOut)
	return fpOut
}

// NegFourierAssign computes fpOut = -fp0.
func (e *Evaluator[T]) NegFourierAssign(fp0, fpOut FourierPoly) {
	negCmplxAssign(fp0.Coeffs, fpOut.Coeffs)
}

// FloatMulFourier returns c * fp0.
func (e *Evaluator[T]) FloatMulFourier(fp0 FourierPoly, c float64) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.FloatMulFourierAssign(fp0, c, fpOut)
	return fpOut
}

// FloatMulFourierAssign computes fpOut = c * fp0.
func (e *Evaluator[T]) FloatMulFourierAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulAddFourierAssign computes fpOut += c * fp0.
func (e *Evaluator[T]) FloatMulAddFourierAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// FloatMulSubFourierAssign computes fpOut -= c * fp0.
func (e *Evaluator[T]) FloatMulSubFourierAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	floatMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulFourier returns c * fp0.
func (e *Evaluator[T]) CmplxMulFourier(fp0 FourierPoly, c complex128) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.CmplxMulFourierAssign(fp0, c, fpOut)
	return fpOut
}

// CmplxMulFourierAssign computes fpOut = c * fp0.
func (e *Evaluator[T]) CmplxMulFourierAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulAddFourierAssign computes fpOut += c * fp0.
func (e *Evaluator[T]) CmplxMulAddFourierAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulAddCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// CmplxMulSubFourierAssign computes fpOut -= c * fp0.
func (e *Evaluator[T]) CmplxMulSubFourierAssign(fp0 FourierPoly, c complex128, fpOut FourierPoly) {
	cmplxMulSubCmplxAssign(fp0.Coeffs, c, fpOut.Coeffs)
}

// MulFourier returns fp0 * fp1.
func (e *Evaluator[T]) MulFourier(fp0, fp1 FourierPoly) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.MulFourierAssign(fp0, fp1, fpOut)
	return fpOut
}

// MulFourierAssign computes fpOut = fp0 * fp1.
func (e *Evaluator[T]) MulFourierAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddFourierAssign computes fpOut += fp0 * fp1.
func (e *Evaluator[T]) MulAddFourierAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulAddCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubFourierAssign computes fpOut -= fp0 * fp1.
func (e *Evaluator[T]) MulSubFourierAssign(fp0, fp1, fpOut FourierPoly) {
	elementWiseMulSubCmplxAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMulFourier returns p * fp0 as FourierPoly.
func (e *Evaluator[T]) PolyMulFourier(fp0 FourierPoly, p Poly[T]) FourierPoly {
	fpOut := e.NewFourierPoly()
	e.PolyMulFourierAssign(fp0, p, fpOut)
	return fpOut
}

// PolyMulFourierAssign computes fpOut = p * fp0.
func (e *Evaluator[T]) PolyMulFourierAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fpMul)

	elementWiseMulCmplxAssign(fp0.Coeffs, e.buffer.fpMul.Coeffs, fpOut.Coeffs)
}

// PolyMulAddFourierAssign computes fpOut += p * fp0.
func (e *Evaluator[T]) PolyMulAddFourierAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fpMul)

	elementWiseMulAddCmplxAssign(fp0.Coeffs, e.buffer.fpMul.Coeffs, fpOut.Coeffs)
}

// PolyMulSubFourierAssign computes fpOut -= p * fp0.
func (e *Evaluator[T]) PolyMulSubFourierAssign(fp0 FourierPoly, p Poly[T], fpOut FourierPoly) {
	e.ToFourierPolyAssign(p, e.buffer.fpMul)

	elementWiseMulSubCmplxAssign(fp0.Coeffs, e.buffer.fpMul.Coeffs, fpOut.Coeffs)
}
