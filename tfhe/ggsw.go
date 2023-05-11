package tfhe

// GGSWCiphertext represents an encrypted GGSW ciphertext.
// which is a GLWEDimension+1 collection of GLev ciphertexts.
type GGSWCiphertext[T Tint] struct {
	// Value has length GLWEDimension + 1.
	Value []GLevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewGGSWCiphertext allocates an empty GGSW ciphertext.
func NewGGSWCiphertext[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) GGSWCiphertext[T] {
	ct := make([]GLevCiphertext[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		ct[i] = NewGLevCiphertext(params, decompParams)
	}
	return GGSWCiphertext[T]{Value: ct, decompParams: decompParams}
}

// Copy returns a copy of the ciphertext.
func (ct GGSWCiphertext[T]) Copy() GGSWCiphertext[T] {
	ctCopy := make([]GLevCiphertext[T], len(ct.Value))
	for i := range ct.Value {
		ctCopy[i] = ct.Value[i].Copy()
	}
	return GGSWCiphertext[T]{Value: ctCopy, decompParams: ct.decompParams}
}

// CopyFrom copies values from a ciphertext.
func (ct *GGSWCiphertext[T]) CopyFrom(ctIn GGSWCiphertext[T]) {
	for i := range ct.Value {
		ct.Value[i].CopyFrom(ctIn.Value[i])
	}
	ct.decompParams = ctIn.decompParams
}

// DecompositionParameters returns the decomposition parameters of the ciphertext.
func (ct GGSWCiphertext[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
