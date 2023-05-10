package poly

import (
	"github.com/sp301415/tfhe/math/num"
)

const (
	// KaratsubaRecurseThreshold is the minimum degree of plaintext to perform karatsuba multiplication.
	// If polynomial's degree equals this value, then the recursive algorithm switches to textbook multiplication.
	KaratsubaRecurseThreshold = 64
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

// karatsubaTreeIndex returns the index of the buffer value
// based on depth and index.
func karatsubaTreeIndex(depth, index int) int {
	return ((num.Pow(3, depth) - 1) / 2) + index
}

// newKaratsubaBuffer allocates a slice of karatsuba buffer.
// Each value of the buffer can be accessed with karatsubaTreeIndex.
func newKaratsubaBuffer[T num.Integer](N int) []karatsubaBuffer[T] {
	// The full depth of the tree = log2(N / KaratsubaThreshold)
	fullDepth := num.Log2(N / KaratsubaRecurseThreshold)
	// Number of nodes = 3^0 + 3^1 + ... + 3^depth = (3^(depth+1) - 1) / 2
	buff := make([]karatsubaBuffer[T], (num.Pow(3, fullDepth+1)-1)/2)

	for i := 0; i < fullDepth; i++ {
		for j := 0; j < num.Pow(3, i); j++ {
			treeIdx := karatsubaTreeIndex(i, j)

			// In depth i, karatsuba inputs have size N / 2^i
			buff[treeIdx] = karatsubaBuffer[T]{
				a0: make([]T, N>>(i+1)),
				a1: make([]T, N>>(i+1)),
				d0: make([]T, N>>i),
				d1: make([]T, N>>i),
				d2: make([]T, N>>i),
			}
		}
	}

	return buff
}

// mulInPlaceNaive multiplies two polynomials using schoolbook method,
// taking O(N^2) time.
func (e Evaluater[T]) mulInPlaceNaive(p0, p1, pOut Poly[T]) {
	pOut.Clear()
	for i := 0; i < e.degree; i++ {
		e.MonomialMulAddAssign(p0, p1.Coeffs[i], i, pOut)
	}
}

// mulInPlaceKaratsuba multiplies two polynomials using recursive karatsuba multiplication,
// taking O(N^1.58) time.
func (e Evaluater[T]) mulInPlaceKaratsuba(p, q, pOut Poly[T]) {
	// Implementation Note:
	// Seems like using range-based loops are faster than regular loops.

	N := e.degree
	buff := e.buffer.karatsubaBuffer[0]

	// p = p0 * X^N/2 + p1
	p0, p1 := p.Coeffs[:N/2], p.Coeffs[N/2:]
	// q = q0 * X^N/2 + q1
	q0, q1 := q.Coeffs[:N/2], q.Coeffs[N/2:]

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, 1, 0)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, 1, 1)

	// a0 := p0 + p1
	// a1 := q0 + q1
	for i := 0; i < N/2; i++ {
		buff.a0[i] = p0[i] + p1[i]
		buff.a1[i] = q0[i] + q1[i]
	}

	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + d0 + d1
	e.karatsuba(buff.a0, buff.a1, buff.d2, 1, 2)

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
func (e Evaluater[T]) karatsuba(p, q, pOut []T, depth, index int) {
	N := len(p)

	if N <= KaratsubaRecurseThreshold {
		// Multiply naively
		for i := range pOut {
			pOut[i] = 0
		}

		for i, cp := range p {
			for j, cq := range q {
				pOut[i+j] += cp * cq
			}
		}
		return
	}

	treeIdx := karatsubaTreeIndex(depth, index)
	buff := e.buffer.karatsubaBuffer[treeIdx]

	// p = p0 * X^N/2 + p1
	p0, p1 := p[:N/2], p[N/2:]
	// q = q0 * X^N/2 + q1
	q0, q1 := q[:N/2], q[N/2:]

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, depth+1, 3*index+0)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, depth+1, 3*index+1)

	// a0 := p0 + p1
	for i := range buff.a0 {
		buff.a0[i] = p0[i] + p1[i]
	}
	// a1 := q0 + q1
	for i := range buff.a1 {
		buff.a1[i] = q0[i] + q1[i]
	}

	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + d0 + d1
	e.karatsuba(buff.a0, buff.a1, buff.d2, depth+1, 3*index+2)

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
