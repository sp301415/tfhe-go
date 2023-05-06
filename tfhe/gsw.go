package tfhe

// GSWCiphertext represents an encrypted GSW ciphertext.
// GSW ciphertext is a collection of leveled LWE ciphertexts.
type GSWCiphertext[T Tint] struct {
	// Value is ordered as [n+1][l]LWECiphertext.
	Value [][]LWECiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGSWCiphertext allocates an empty GSW ciphertext.
//
// Panics if decompParams is invalid.
func NewGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	ct := make([][]LWECiphertext[T], params.lweDimension+1)
	for i := 0; i < params.lweDimension+1; i++ {
		ct[i] = make([]LWECiphertext[T], decompParams.level)
		for j := 0; j < decompParams.level; j++ {
			ct[i][j] = NewLWECiphertext(params)
		}
	}
	return GSWCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct GSWCiphertext[T]) Copy() GSWCiphertext[T] {
	c := make([][]LWECiphertext[T], len(ct.Value))
	for i := range c {
		c[i] = make([]LWECiphertext[T], len(ct.Value[i]))
		for j := range c[i] {
			c[i][j] = ct.Value[i][j].Copy()
		}
	}
	return GSWCiphertext[T]{Value: c, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct GSWCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}

// ToLev returns the last row, which is the Lev ciphertext of original message.
func (ct GSWCiphertext[T]) ToLev() []LWECiphertext[T] {
	return ct.Value[len(ct.Value)-1]
}
