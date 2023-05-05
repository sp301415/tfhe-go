package tfhe

import "github.com/sp301415/tfhe/math/num"

// GGSWCiphertext represents an encrypted GGSW ciphertext.
// GGSW ciphertext is a collection of leveled GLWE ciphertexts,
// ordered as [k+1][l]GLWECiphertext.
type GGSWCiphertext[T Tint] struct {
	value [][]GLWECiphertext[T]

	// base of Gadget Decomposition
	base int
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
// base should be power of two. Otherwise, it panics.
func NewGGSWCiphertext[T Tint](params Parameters[T], base int, level int) GGSWCiphertext[T] {
	if !num.IsPowerOfTwo(base) {
		panic("base not power of two")
	}

	ct := make([][]GLWECiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = make([]GLWECiphertext[T], level)
		for j := 0; j < level; j++ {
			ct[i][j] = NewGLWECiphertext(params)
		}
	}
	return GGSWCiphertext[T]{value: ct, base: base}
}

// Copy returns a copy of the ciphertext.
func (ct GGSWCiphertext[T]) Copy() GGSWCiphertext[T] {
	c := make([][]GLWECiphertext[T], len(ct.value))
	for i := range c {
		c[i] = make([]GLWECiphertext[T], len(ct.value[i]))
		for j := range c[i] {
			c[i][j] = ct.value[i][j].Copy()
		}
	}
	return GGSWCiphertext[T]{value: c, base: ct.base}
}

// Len returns the length of the ciphertext.
func (ct GGSWCiphertext[T]) Len() int {
	return len(ct.value)
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct GGSWCiphertext[T]) Degree() int {
	return ct.value[0][0].Degree()
}

// Level returns the level of the ciphertext.
func (ct GGSWCiphertext[T]) Level() int {
	return len(ct.value[0])
}

// Base returns the gadget base of the ciphertext.
func (ct GGSWCiphertext[T]) Base() int {
	return ct.base
}
