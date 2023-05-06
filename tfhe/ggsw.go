package tfhe

// GGSWCiphertext represents an encrypted GGSW ciphertext.
// GGSW ciphertext is a collection of leveled GLWE ciphertexts,
// ordered as [k+1][l]GLWECiphertext.
type GGSWCiphertext[T Tint] struct {
	Value [][]GLWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
//
// Panics if decompParams is invalid.
func NewGGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	if err := decompParams.IsValid(); err != nil {
		panic(err)
	}

	ct := make([][]GLWECiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = make([]GLWECiphertext[T], decompParams.Level)
		for j := 0; j < decompParams.Level; j++ {
			ct[i][j] = NewGLWECiphertext(params)
		}
	}
	return GGSWCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct GGSWCiphertext[T]) Copy() GGSWCiphertext[T] {
	c := make([][]GLWECiphertext[T], len(ct.Value))
	for i := range c {
		c[i] = make([]GLWECiphertext[T], len(ct.Value[i]))
		for j := range c[i] {
			c[i][j] = ct.Value[i][j].Copy()
		}
	}
	return GGSWCiphertext[T]{Value: c, decompParams: ct.decompParams}
}

// Len returns the length of the ciphertext.
func (ct GGSWCiphertext[T]) Len() int {
	return len(ct.Value)
}

// Degree returns the polynomial degree of elements of the ciphertext.
func (ct GGSWCiphertext[T]) Degree() int {
	return ct.Value[0][0].Degree()
}

// Level returns the level of the ciphertext.
func (ct GGSWCiphertext[T]) Level() int {
	return len(ct.Value[0])
}

// Base returns the gadget base of the ciphertext.
func (ct GGSWCiphertext[T]) Base() T {
	return ct.decompParams.Base
}
