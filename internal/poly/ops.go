package poly

// Add adds p0, p1 and returns the result.
func (e Evaluater[T]) Add(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.AddInPlace(p0, p1, p)
	return p
}

// AddInPlace adds p0, p1 and writes it to pOut.
func (e Evaluater[T]) AddInPlace(p0, p1, pOut Poly[T]) {
	e.checkDegree(p0, p1, pOut)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = p0.Coeffs[i] + p1.Coeffs[i]
	}
}

// AddAssign adds p0, pOut and writes it to pOut.
func (e Evaluater[T]) AddAssign(p0, pOut Poly[T]) {
	e.AddInPlace(p0, pOut, pOut)
}

// Sub subtracts p0, p1 and returns the result.
func (e Evaluater[T]) Sub(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.SubInPlace(p0, p1, p)
	return p
}

// SubInPlace subtracts p0, p1 and writes it to pOut.
func (e Evaluater[T]) SubInPlace(p0, p1, pOut Poly[T]) {
	e.checkDegree(p0, p1, pOut)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = p0.Coeffs[i] - p1.Coeffs[i]
	}
}

// SubAssign subtracts p0 from pOut and writes it to pOut.
func (e Evaluater[T]) SubAssign(p0, pOut Poly[T]) {
	e.SubInPlace(pOut, p0, pOut)
}

// Mul multiplies p0, p1 and returns the result.
func (e Evaluater[T]) Mul(p0, p1 Poly[T]) Poly[T] {
	p := New[T](e.degree)
	e.MulInPlace(p0, p1, p)
	return p
}

// MulInPlace multiplies p0, p1 and writes it to pOut.
func (e Evaluater[T]) MulInPlace(p0, p1, pOut Poly[T]) {
	e.checkDegree(p0, p1, pOut)

	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = T(e.buffpOutf[i])
	}
}

// MulAssign multiplies p0, pOut and writes it to pOut.
func (e Evaluater[T]) MulAssign(p0, pOut Poly[T]) {
	e.MulInPlace(p0, pOut, pOut)
}

// MulAddAssign multiplies p0, p1 and adds to pOut.
func (e Evaluater[T]) MulAddAssign(p0, p1, pOut Poly[T]) {
	e.checkDegree(p0, p1, pOut)

	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] += T(e.buffpOutf[i])
	}
}

// MulSubAssign multiplies p0, p1 and subtracts from pOut.
func (e Evaluater[T]) MulSubAssign(p0, p1, pOut Poly[T]) {
	e.checkDegree(p0, p1, pOut)

	for i := 0; i < e.degree; i++ {
		e.buffp0f[i] = float64(p0.Coeffs[i])
		e.buffp1f[i] = float64(p1.Coeffs[i])
	}

	e.convolve(e.buffp0f, e.buffp1f, e.buffpOutf)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] -= T(e.buffpOutf[i])
	}
}

// ScalarMul multplies c to p0 and returns the result.
func (e Evaluater[T]) ScalarMul(p0 Poly[T], c T) Poly[T] {
	p := New[T](e.degree)
	e.ScalarMulInPlace(p0, c, p)
	return p
}

// ScalarMulInPlace multplies c to p0 and writes it to pOut.
func (e Evaluater[T]) ScalarMulInPlace(p0 Poly[T], c T, pOut Poly[T]) {
	e.checkDegree(p0, pOut)

	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = c * p0.Coeffs[i]
	}
}

// ScalarMulAssign multplies c to pOut and writes it to pOut.
func (e Evaluater[T]) ScalarMulAssign(c T, pOut Poly[T]) {
	e.ScalarMulInPlace(pOut, c, pOut)
}
