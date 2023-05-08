package tfhe

// GSWCiphertext represents an encrypted GSW ciphertext,
// which is a LWEDimension+1 collection of Lev ciphertexts.
type GSWCiphertext[T Tint] struct {
	// Value has length LWEDimension + 1.
	Value []LevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGSWCiphertext allocates an empty GSW ciphertext.
func NewGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GSWCiphertext[T] {
	ct := make([]LevCiphertext[T], params.lweDimension+1)
	for i := 0; i < params.lweDimension+1; i++ {
		ct[i] = NewLevCiphertext(params, decompParams)
	}
	return GSWCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct GSWCiphertext[T]) Copy() GSWCiphertext[T] {
	ctCopy := make([]LevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GSWCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct GSWCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}

// ToLev returns the last row, which is the Lev ciphertext of original message.
func (ct GSWCiphertext[T]) ToLev() LevCiphertext[T] {
	return ct.Value[ct.decompParams.level-1]
}
