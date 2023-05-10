package poly

import (
	"github.com/sp301415/tfhe/math/num"
	"github.com/sp301415/tfhe/math/vec"
)

const (
	// KaratsubaRecurseThreshold is the minimum degree of plaintext to perform karatsuba multiplication.
	// If polynomial's degree equals this value, then the recursive algorithm switches to textbook multiplication.
	KaratsubaRecurseThreshold = 64
)

// karatsubaBuffer contains vuffer values for each karatsuba multiplication.
type karatsubaBuffer[T num.Integer] struct {
	// a0 = p0 + q0
	a0 Poly[T]
	// a1 = p1 + q1
	a1 Poly[T]
	// d0 = karatsuba(p0, q0)
	d0 Poly[T]
	// d1 = karatsuba(p1, q1)
	d1 Poly[T]
	// d2 = karatsuba(a0, a1)
	d2 Poly[T]
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
			NN := N >> i
			buff[treeIdx] = karatsubaBuffer[T]{
				a0: New[T](NN / 2),
				a1: New[T](NN / 2),
				d0: New[T](NN),
				d1: New[T](NN),
				d2: New[T](NN),
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
	N := e.degree
	buff := e.buffer.karatsubaBuffer[0]

	// p = p0 * X^N/2 + p1
	p0 := From(p.Coeffs[:N/2])
	p1 := From(p.Coeffs[N/2:])
	// q = q0 * X^N/2 + q1
	q0 := From(q.Coeffs[:N/2])
	q1 := From(q.Coeffs[N/2:])

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, 1, 0)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, 1, 1)

	// a0 := p0 + p1
	e.AddInPlace(p0, p1, buff.a0)
	// a1 := q0 + q1
	e.AddInPlace(q0, q1, buff.a1)
	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + a0 + a1
	e.karatsuba(buff.a0, buff.a1, buff.d2, 1, 2)

	// d2 := d2 - a0 - a1 = p0*q1 + p1*q0
	vec.SubAssign(buff.d0.Coeffs, buff.d2.Coeffs)
	vec.SubAssign(buff.d1.Coeffs, buff.d2.Coeffs)

	// pOut := d0 + d2*X^N/2 + d1*X^N
	vec.CopyAssign(buff.d0.Coeffs, pOut.Coeffs[0:N])        // d0: 0 ~ N
	vec.AddAssign(buff.d2.Coeffs[:N/2], pOut.Coeffs[N/2:N]) // d2: N/2 ~ N
	vec.SubAssign(buff.d2.Coeffs[N/2:], pOut.Coeffs[:N/2])  // -d2: 0 ~ N/2
	vec.SubAssign(buff.d1.Coeffs, pOut.Coeffs[0:N])         // -d1: 0 ~ N
}

// karatsuba is a recursive subroutine of karatsuba algorithm.
// Degree of pOut is assumbed to be twice of degree of p and q.
func (e Evaluater[T]) karatsuba(p, q, pOut Poly[T], depth, index int) {
	N := p.Degree()

	if N <= KaratsubaRecurseThreshold {
		// Multiply naively
		pOut.Clear()
		for i := 0; i < N; i++ {
			for j := 0; j < N; j++ {
				pOut.Coeffs[i+j] += p.Coeffs[i] * q.Coeffs[j]
			}
		}
		return
	}

	treeIdx := karatsubaTreeIndex(depth, index)
	buff := e.buffer.karatsubaBuffer[treeIdx]

	// p = p0 * X^N/2 + p1
	p0 := From(p.Coeffs[:N/2])
	p1 := From(p.Coeffs[N/2:])
	// q = q0 * X^N/2 + q1
	q0 := From(q.Coeffs[:N/2])
	q1 := From(q.Coeffs[N/2:])

	// d0 := p0 * q0
	e.karatsuba(p0, q0, buff.d0, depth+1, 3*index+0)
	// d1 := p1 * q1
	e.karatsuba(p1, q1, buff.d1, depth+1, 3*index+1)

	// a0 := p0 + p1
	e.AddInPlace(p0, p1, buff.a0)
	// a1 := q0 + q1
	e.AddInPlace(q0, q1, buff.a1)
	// d2 := (p0 + p1) * (q0 + q1) = p0*q0 + p0*q1 + p1*q0 + p1*q1 = (p0*q1 + p1*q0) + a0 + a1
	e.karatsuba(buff.a0, buff.a1, buff.d2, depth+1, 3*index+2)

	// d2 := d2 - a0 - a1 = p0*q1 + p1*q0
	vec.SubAssign(buff.d0.Coeffs, buff.d2.Coeffs)
	vec.SubAssign(buff.d1.Coeffs, buff.d2.Coeffs)

	// pOut := d0 + d2*X^N/2 + d1*X^N
	vec.CopyAssign(buff.d0.Coeffs, pOut.Coeffs[0:N])      // d0: 0 ~ N
	vec.CopyAssign(buff.d1.Coeffs, pOut.Coeffs[N:2*N])    // d1: N ~ 2N
	vec.AddAssign(buff.d2.Coeffs, pOut.Coeffs[N/2:3*N/2]) // d2: N/2 ~ 3N/2
}
