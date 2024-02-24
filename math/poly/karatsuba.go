package poly

import (
	"github.com/sp301415/tfhe-go/math/num"
)

const (
	// karatsubaRecurseThreshold is the minimum degree of plaintext to perform karatsuba multiplication.
	// If polynomial's degree equals this value, then the recursive algorithm switches to textbook multiplication.
	karatsubaRecurseThreshold = 64
)

// karatsubaBuffer contains vuffer values for each karatsuba multiplication.
type karatsubaBuffer[T num.Integer] struct {
	// a0 = p0 + q0
	a0 []T
	// a1 = p1 + q1
	a1 []T
	// d0 = karatsuba(p0, q0)
	d0 []T
	// d1 = karatsuba(p1, q1)
	d1 []T
	// d2 = karatsuba(a0, a1)
	d2 []T
}

// newKaratsubaBuffer allocates a slice of karatsuba buffer.
// Each value of the buffer can be accessed with karatsubaTreeIndex.
func newKaratsubaBuffer[T num.Integer](N int) []karatsubaBuffer[T] {
	// The full depth of the tree = log2(N / KaratsubaThreshold)
	fullDepth := num.Log2(N / karatsubaRecurseThreshold)
	// We only need fullDepth buffers.
	buff := make([]karatsubaBuffer[T], fullDepth)
	for i := 0; i < fullDepth; i++ {
		// In depth i, karatsuba inputs have size N / 2^i
		buff[i] = karatsubaBuffer[T]{
			a0: make([]T, N>>(i+1)),
			a1: make([]T, N>>(i+1)),
			d0: make([]T, N>>i),
			d1: make([]T, N>>i),
			d2: make([]T, N>>i),
		}
	}

	return buff
}

// mulNaive multiplies two polynomials using schoolbook method,
// taking O(N^2) time.
func (e *Evaluator[T]) mulNaive(p0, p1 Poly[T]) Poly[T] {
	pOut := e.NewPoly()
	e.mulNaiveAssign(p0, p1, pOut)
	return pOut
}

// mulNaiveAssign multiplies two polynomials using schoolbook method,
// taking O(N^2) time.
func (e *Evaluator[T]) mulNaiveAssign(p0, p1, pOut Poly[T]) {
	for i := 0; i < e.degree; i++ {
		pOut.Coeffs[i] = p0.Coeffs[i] * p1.Coeffs[0]
	}

	for i := 0; i < e.degree; i++ {
		for j := 1; j < e.degree; j++ {
			if i+j < e.degree {
				pOut.Coeffs[i+j] += p0.Coeffs[i] * p1.Coeffs[j]
			} else {
				pOut.Coeffs[i+j-e.degree] -= p0.Coeffs[i] * p1.Coeffs[j]
			}
		}
	}
}

// mulKaratsubaAssign multiplies two polynomials using recursive karatsuba multiplication,
// taking O(N^1.58) time.
func (e *Evaluator[T]) mulKaratsubaAssign(p, q, pOut Poly[T]) {
	// Implementation Note:
	// Seems like using range-based loops are faster than regular loops.

	N := e.degree
	karatsubaBuffer := newKaratsubaBuffer[T](N)

	buff := karatsubaBuffer[0]

	// p = p0 * X^N/2 + p1
	p0, p1 := p.Coeffs[:N/2], p.Coeffs[N/2:]
	// q = q0 * X^N/2 + q1
	q0, q1 := q.Coeffs[:N/2], q.Coeffs[N/2:]

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, 1, karatsubaBuffer)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, 1, karatsubaBuffer)

	// a0 := p0 + p1
	for i := range buff.a0 {
		buff.a0[i] = p0[i] + p1[i]
	}
	// a1 := q0 + q1
	for i := range buff.a1 {
		buff.a1[i] = q0[i] + q1[i]
	}

	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + d0 + d1
	e.karatsuba(buff.a0, buff.a1, buff.d2, 1, karatsubaBuffer)

	// pOut := d0 + (d2 - d0 - d1)*X^N/2 + d1*X^N
	for i := range pOut.Coeffs {
		if i < N/2 {
			pOut.Coeffs[i] = buff.d0[i] - (buff.d2[i+N/2] - buff.d0[i+N/2] - buff.d1[i+N/2]) - buff.d1[i] // d0 + (d2 - d0 - d1) - d1: 0 ~ N/2
		} else {
			pOut.Coeffs[i] = buff.d0[i] + (buff.d2[i-N/2] - buff.d0[i-N/2] - buff.d1[i-N/2]) - buff.d1[i] // d0 - (d2 - d0 - d1) + d1: N/2 ~ N
		}
	}
}

// karatsuba is a recursive subroutine of karatsuba algorithm.
// length of pOut is assumed to be twice of length of p and q.
func (e *Evaluator[T]) karatsuba(p, q, pOut []T, depth int, karatsubaBuffer []karatsubaBuffer[T]) {
	N := len(p)

	if N <= karatsubaRecurseThreshold {
		// Multiply naively
		for i := range pOut {
			pOut[i] = 0
		}

		for i := range p {
			for j := range q {
				pOut[i+j] += p[i] * q[j]
			}
		}
		return
	}

	buff := karatsubaBuffer[depth]

	// p = p0 * X^N/2 + p1
	p0, p1 := p[:N/2], p[N/2:]
	// q = q0 * X^N/2 + q1
	q0, q1 := q[:N/2], q[N/2:]

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, depth+1, karatsubaBuffer)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, depth+1, karatsubaBuffer)

	// a0 := p0 + p1
	for i := range buff.a0 {
		buff.a0[i] = p0[i] + p1[i]
	}
	// a1 := q0 + q1
	for i := range buff.a1 {
		buff.a1[i] = q0[i] + q1[i]
	}

	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + d0 + d1
	e.karatsuba(buff.a0, buff.a1, buff.d2, depth+1, karatsubaBuffer)

	// pOut := d0 + (d2 - d0 - d1)*X^N/2 + d1*X^N
	for i := range pOut {
		if i < N {
			pOut[i] = buff.d0[i] // d0: 0 ~ N
		}
		if N <= i {
			pOut[i] = buff.d1[i-N] // d1: N ~ 2N
		}
		if N/2 <= i && i < 3*N/2 {
			pOut[i] += buff.d2[i-N/2] - buff.d0[i-N/2] - buff.d1[i-N/2] // d2 -d0 - d1: N/2 ~ 3N/2
		}
	}
}
