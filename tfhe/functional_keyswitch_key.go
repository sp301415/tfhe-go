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

// PublicFunctionalLWEKeySwitchKey is a keyswitch key for LWE public functional keyswitching.
type PublicFunctionalLWEKeySwitchKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []LevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewPublicFunctionalLWEKeySwitchKey allocates an empty PublicFunctionalLWEKeySwitchKey.
func NewPublicFunctionalLWEKeySwitchKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) PublicFunctionalLWEKeySwitchKey[T] {
	pfksk := make([]LevCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		pfksk[i] = NewLevCiphertext(params, decompParams)
	}
	return PublicFunctionalLWEKeySwitchKey[T]{Value: pfksk, decompParams: decompParams}
}

// Copy copies this key.
func (pfksk PublicFunctionalLWEKeySwitchKey[T]) Copy() PublicFunctionalLWEKeySwitchKey[T] {
	pfkskCopy := make([]LevCiphertext[T], len(pfksk.Value))
	for i := range pfksk.Value {
		pfkskCopy[i] = pfksk.Value[i].Copy()
	}
	return PublicFunctionalLWEKeySwitchKey[T]{Value: pfkskCopy, decompParams: pfksk.decompParams}
}

// CopyFrom copies values from key.
func (pfksk *PublicFunctionalLWEKeySwitchKey[T]) CopyFrom(pfkskIn PublicFunctionalLWEKeySwitchKey[T]) {
	for i := range pfksk.Value {
		pfksk.Value[i].CopyFrom(pfkskIn.Value[i])
	}
	pfksk.decompParams = pfkskIn.decompParams
}

// PublicFunctionalGLWEKeySwitchKey is a keyswitch key for GLWE public functional keyswitching.
type PublicFunctionalGLWEKeySwitchKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []FourierGLevCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewPublicFunctionalGLWEKeySwitchKey allocates an empty PublicFunctionalGLWEKeySwitchKey.
func NewPublicFunctionalGLWEKeySwitchKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) PublicFunctionalGLWEKeySwitchKey[T] {
	pfksk := make([]FourierGLevCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		pfksk[i] = NewFourierGLevCiphertext(params, decompParams)
	}
	return PublicFunctionalGLWEKeySwitchKey[T]{Value: pfksk, decompParams: decompParams}
}

// Copy copies this key.
func (pfksk PublicFunctionalGLWEKeySwitchKey[T]) Copy() PublicFunctionalGLWEKeySwitchKey[T] {
	pfkskCopy := make([]FourierGLevCiphertext[T], len(pfksk.Value))
	for i := range pfksk.Value {
		pfkskCopy[i] = pfksk.Value[i].Copy()
	}
	return PublicFunctionalGLWEKeySwitchKey[T]{Value: pfkskCopy, decompParams: pfksk.decompParams}
}

// CopyFrom copies values from key.
func (pfksk *PublicFunctionalGLWEKeySwitchKey[T]) CopyFrom(pfkskIn PublicFunctionalGLWEKeySwitchKey[T]) {
	for i := range pfksk.Value {
		pfksk.Value[i].CopyFrom(pfkskIn.Value[i])
	}
	pfksk.decompParams = pfkskIn.decompParams
}

// CircuitBootstrapKey is a bootstrap key for circuit bootstrapping.
// It is a collection of PrivateFunctionalGLWEKeySwitchKeys,
// each encoding function f_i = -GLWEKey_i * x.
type CircuitBootstrapKey[T Tint] struct {
	// Value has length GLWEDimension + 1,
	// each PrivateFunctionalGLWEKeySwitchKey having 1 inputCount.
	Value []PrivateFunctionalGLWEKeySwitchKey[T]

	decompParams DecompositionParameters[T]
}

// NewCircuitBootstrapKey allocates an empty CircuitBootstrapKey.
func NewCircuitBootstrapKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) CircuitBootstrapKey[T] {
	cbsk := make([]PrivateFunctionalGLWEKeySwitchKey[T], params.glweDimension+1)
	for i := 0; i < params.glweDimension+1; i++ {
		cbsk[i] = NewPrivateFunctionalGLWEKeySwitchKey(params, 1, decompParams)
	}
	return CircuitBootstrapKey[T]{Value: cbsk, decompParams: decompParams}
}

// Copy copies this key.
func (cbsk CircuitBootstrapKey[T]) Copy() CircuitBootstrapKey[T] {
	cbskCopy := make([]PrivateFunctionalGLWEKeySwitchKey[T], len(cbsk.Value))
	for i := range cbsk.Value {
		cbskCopy[i] = cbsk.Value[i].Copy()
	}
	return CircuitBootstrapKey[T]{Value: cbskCopy, decompParams: cbsk.decompParams}
}

// CopyFrom copies values from key.
func (cbsk *CircuitBootstrapKey[T]) CopyFrom(cbskIn CircuitBootstrapKey[T]) {
	for i := range cbsk.Value {
		cbsk.Value[i].CopyFrom(cbskIn.Value[i])
	}
	cbsk.decompParams = cbskIn.decompParams
}
