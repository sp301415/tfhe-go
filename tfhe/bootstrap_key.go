package tfhe

// BootstrappingKey is a key for bootstrapping.
// Essentially, this is a GGSW encryption of LWE key with GLWE key.
// However, FFT is already applied for fast external product.
type BootstrappingKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []FourierGGSWCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewBootstrappingKey allocates an empty BootstrappingKey.
func NewBootstrappingKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) BootstrappingKey[T] {
	bsk := make([]FourierGGSWCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		bsk[i] = NewFourierGGSWCiphertext(params, decompParams)
	}
	return BootstrappingKey[T]{Value: bsk, decompParams: decompParams}
}

// Copy returns a copy of the key.
func (bsk BootstrappingKey[T]) Copy() BootstrappingKey[T] {
	bskCopy := make([]FourierGGSWCiphertext[T], len(bsk.Value))
	for i := range bsk.Value {
		bskCopy[i] = bsk.Value[i].Copy()
	}
	return BootstrappingKey[T]{Value: bskCopy, decompParams: bsk.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the key.
func (bsk BootstrappingKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return bsk.decompParams
}

// KeySwitchingKey is a LWE keyswitching key from GLWE secret key to LWE secret key.
// Essentially, this is a GSW encryption of GLWE key with LWE key.
type KeySwitchingKey[T Tint] GSWCiphertext[T]

// NewKeySwitchingKey allocates an empty KeySwitchingKey.
func NewKeySwitchingKey[T Tint](inputDimension, outputDimension int, decompParams DecompositionParameters[T]) KeySwitchingKey[T] {
	kswKey := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		kswKey[i] = LevCiphertext[T]{Value: make([]LWECiphertext[T], decompParams.level), decompParams: decompParams}
		for j := 0; j < decompParams.level; j++ {
			kswKey[i].Value[j] = LWECiphertext[T]{Value: make([]T, outputDimension+1)}
		}
	}
	return KeySwitchingKey[T]{Value: kswKey, decompParams: decompParams}
}

// InputLWEDimension returns the input LWEDimension of this key.
func (ksk KeySwitchingKey[T]) InputLWEDimension() int {
	return len(ksk.Value)
}

// OutputLWEDimension returns the output LWEDimension of this key.
func (ksk KeySwitchingKey[T]) OutputLWEDimension() int {
	return len(ksk.Value[0].Value[0].Value) - 1
}

// Copy returns a copy of the key.
func (ksk KeySwitchingKey[T]) Copy() KeySwitchingKey[T] {
	return KeySwitchingKey[T](GSWCiphertext[T](ksk).Copy())
}

// DecompositionParameters returns the decomposition parameters of the key.
func (ct KeySwitchingKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
