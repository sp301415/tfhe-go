package tfhe

// GGSWCiphertext represents an encrypted GGSW ciphertext.
// GGSW ciphertext is a collection of leveled GLWE ciphertexts,
type GGSWCiphertext[T Tint] struct {
	// Value is ordered as [k+1][l]GLWECiphertext.
	Value [][]GLWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
//
// Panics if decompParams is invalid.
func NewGGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ct := make([][]GLWECiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = make([]GLWECiphertext[T], decompParams.level)
		for j := 0; j < decompParams.level; j++ {
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

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct GGSWCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}

// ToGLev returns the last row, which is the GLev ciphertext of original message.
func (ct GGSWCiphertext[T]) ToGLev() []GLWECiphertext[T] {
	return ct.Value[len(ct.Value)-1]
}
