package poly

import "github.com/sp301415/tfhe-go/math/vec"

// Add adds fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Add(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.AddAssign(fp0, fp1, fp)
	return fp
}

// AddAssign adds fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) AddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.AddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Sub subtracts fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Sub(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.SubAssign(fp0, fp1, fp)
	return fp
}

// SubAssign subtracts fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) SubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.SubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// Neg negates fp0 and returns the result.
func (f *FourierEvaluator[T]) Neg(fp0 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.NegAssign(fp0, fp)
	return fp
}

// NegAssign negates fp0 and writes it to fpOut.
func (f *FourierEvaluator[T]) NegAssign(fp0, fpOut FourierPoly) {
	vec.NegAssign(fp0.Coeffs, fpOut.Coeffs)
}

// Mul multiplies fp0, fp1 and returns the result.
func (f *FourierEvaluator[T]) Mul(fp0, fp1 FourierPoly) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.MulAssign(fp0, fp1, fp)
	return fp
}

// MulAssign multiplies fp0, fp1 and writes it to fpOut.
func (f *FourierEvaluator[T]) MulAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulAddAssign multiplies fp0, fp1 and adds it to fpOut.
func (f *FourierEvaluator[T]) MulAddAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulAddAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// MulSubAssign multiplies fp0, fp1 and subtracts it from fpOut.
func (f *FourierEvaluator[T]) MulSubAssign(fp0, fp1, fpOut FourierPoly) {
	vec.ElementWiseMulSubAssign(fp0.Coeffs, fp1.Coeffs, fpOut.Coeffs)
}

// PolyMul multiplies fp0, p1 and returns the result.
func (f *FourierEvaluator[T]) PolyMul(fp0 FourierPoly, p1 Poly[T]) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.PolyMulAssign(fp0, p1, fp)
	return fp
}

// PolyMulAssign multiplies fp0, p1 and writes it to fpOut.
func (f *FourierEvaluator[T]) PolyMulAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulAddAssign multiplies fp0, p1 and adds it to fpOut.
func (f *FourierEvaluator[T]) PolyMulAddAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulAddAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// PolyMulSubAssign multiplies fp0, p1 and subtracts it from fpOut.
func (f *FourierEvaluator[T]) PolyMulSubAssign(fp0 FourierPoly, p1 Poly[T], fpOut FourierPoly) {
	f.ToFourierPolyAssign(p1, f.buffer.fp)

	vec.ElementWiseMulSubAssign(fp0.Coeffs, f.buffer.fp.Coeffs, fpOut.Coeffs)
}

// ScalarMul multiplies c to fp0 and returns the result.
func (f *FourierEvaluator[T]) ScalarMul(fp0 FourierPoly, c float64) FourierPoly {
	fp := NewFourierPoly(f.degree)
	f.ScalarMulAssign(fp0, c, fp)
	return fp
}

// ScalarMulAssign multiplies c to fp0 and writes it to fpOut.
func (f *FourierEvaluator[T]) ScalarMulAssign(fp0 FourierPoly, c float64, fpOut FourierPoly) {
	vec.ScalarMulAssign(fp0.Coeffs, complex(c, 0), fpOut.Coeffs)
}
