package tfhe

// PrivateFunctionalLWEKeySwitchKey is a keyswitch key for private functional keyswitching.
// For some linear function f: T^p -> T, keyswitching with this key applies f to
// p LWE ciphertexts, returning one LWE ciphertext.
type PrivateFunctionalLWEKeySwitchKey[T Tint] struct {
	// Value has length InputLWECount.
	Value []GSWCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewPrivateFunctionalLWEKeySwitchKey allocates an empty PrivateFunctionalLWEKeySwitchKey.
func NewPrivateFunctionalLWEKeySwitchKey[T Tint](params Parameters[T], inputCount int, decompParams DecompositionParameters[T]) PrivateFunctionalLWEKeySwitchKey[T] {
	pfksk := make([]GSWCiphertext[T], inputCount)
	for i := 0; i < inputCount; i++ {
		pfksk[i] = NewGSWCiphertext(params, decompParams)
	}
	return PrivateFunctionalLWEKeySwitchKey[T]{Value: pfksk, decompParams: decompParams}
}

// Copy copies this key.
func (pfksk PrivateFunctionalLWEKeySwitchKey[T]) Copy() PrivateFunctionalLWEKeySwitchKey[T] {
	pfkskCopy := make([]GSWCiphertext[T], len(pfksk.Value))
	for i := range pfksk.Value {
		pfkskCopy[i] = pfksk.Value[i].Copy()
	}
	return PrivateFunctionalLWEKeySwitchKey[T]{Value: pfkskCopy, decompParams: pfksk.decompParams}
}

// CopyFrom copies values from key.
func (pfksk *PrivateFunctionalLWEKeySwitchKey[T]) CopyFrom(pfkskIn PrivateFunctionalLWEKeySwitchKey[T]) {
	for i := range pfksk.Value {
		pfksk.Value[i].CopyFrom(pfkskIn.Value[i])
	}
	pfksk.decompParams = pfkskIn.decompParams
}

// InputCount returns the number of LWE ciphertext that can be applied with this key.
func (pfksk PrivateFunctionalLWEKeySwitchKey[T]) InputCount() int {
	return len(pfksk.Value)
}

// PrivateFunctionalGLWEKeySwitchKey is a keyswitch key for private functional keyswitching.
// For some linear function f: T^p -> T_N[X], keyswitching with this key applies f to
// p LWE ciphertexts, returning one GLWE ciphertext.
type PrivateFunctionalGLWEKeySwitchKey[T Tint] struct {
	// Value has length InputLWECount, LWEDimension + 1.
	Value [][]GLevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewPrivateFunctionalGLWEKeySwitchKey allocates an empty PrivateFunctionalGLWEKeySwitchKey.
func NewPrivateFunctionalGLWEKeySwitchKey[T Tint](params Parameters[T], inputCount int, decompParams DecompositionParameters[T]) PrivateFunctionalGLWEKeySwitchKey[T] {
	pfksk := make([][]GLevCiphertext[T], inputCount)
	for i := 0; i < inputCount; i++ {
		pfksk[i] = make([]GLevCiphertext[T], params.lweDimension+1)
		for j := 0; j < params.lweDimension+1; j++ {
			pfksk[i][j] = NewGLevCiphertext(params, decompParams)
		}
	}
	return PrivateFunctionalGLWEKeySwitchKey[T]{Value: pfksk, decompParams: decompParams}
}

// Copy copies this key.
func (pfksk PrivateFunctionalGLWEKeySwitchKey[T]) Copy() PrivateFunctionalGLWEKeySwitchKey[T] {
	pfkskCopy := make([][]GLevCiphertext[T], len(pfksk.Value))
	for i := range pfksk.Value {
		pfkskCopy[i] = make([]GLevCiphertext[T], len(pfksk.Value[i]))
		for j := range pfksk.Value[i] {
			pfkskCopy[i][j] = pfksk.Value[i][j].Copy()
		}
	}
	return PrivateFunctionalGLWEKeySwitchKey[T]{Value: pfkskCopy, decompParams: pfksk.decompParams}
}

// CopyFrom copies values from key.
func (pfksk *PrivateFunctionalGLWEKeySwitchKey[T]) CopyFrom(pfkskIn PrivateFunctionalGLWEKeySwitchKey[T]) {
	for i := range pfksk.Value {
		for j := range pfksk.Value[i] {
			pfksk.Value[i][j].CopyFrom(pfkskIn.Value[i][j])
		}
	}
	pfksk.decompParams = pfkskIn.decompParams
}

// InputCount returns the number of LWE ciphertext that can be applied with this key.
func (pfksk PrivateFunctionalGLWEKeySwitchKey[T]) InputCount() int {
	return len(pfksk.Value)
}
