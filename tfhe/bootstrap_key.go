package tfhe

// BootstrapKey is a key for bootstrapping.
// Essentially, this is a GGSW encryption of LWE key with GLWE key.
// However, FFT is already applied for fast external product.
type BootstrapKey[T Tint] struct {
	// Value has length LWEDimension.
	Value []FourierGGSWCiphertext[T]

	decompParams DecompositionParameters[T]
}

// NewBootstrapKey allocates an empty BootstrappingKey.
func NewBootstrapKey[T Tint](params Parameters[T], decompParams DecompositionParameters[T]) BootstrapKey[T] {
	bsk := make([]FourierGGSWCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		bsk[i] = NewFourierGGSWCiphertext(params, decompParams)
	}
	return BootstrapKey[T]{Value: bsk, decompParams: decompParams}
}

// Copy returns a copy of the key.
func (bsk BootstrapKey[T]) Copy() BootstrapKey[T] {
	bskCopy := make([]FourierGGSWCiphertext[T], len(bsk.Value))
	for i := range bsk.Value {
		bskCopy[i] = bsk.Value[i].Copy()
	}
	return BootstrapKey[T]{Value: bskCopy, decompParams: bsk.decompParams}
}

// DecompositionParameters returns the decomposition parameters of the key.
func (bsk BootstrapKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return bsk.decompParams
}

// KeySwitchKey is a LWE keyswitching key from GLWE secret key to LWE secret key.
// Essentially, this is a GSW encryption of GLWE key with LWE key.
type KeySwitchKey[T Tint] GSWCiphertext[T]

// NewKeySwitchKey allocates an empty KeySwitchingKey.
func NewKeySwitchKey[T Tint](inputDimension, outputDimension int, decompParams DecompositionParameters[T]) KeySwitchKey[T] {
	kswKey := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		kswKey[i] = LevCiphertext[T]{Value: make([]LWECiphertext[T], decompParams.level), decompParams: decompParams}
		for j := 0; j < decompParams.level; j++ {
			kswKey[i].Value[j] = LWECiphertext[T]{Value: make([]T, outputDimension+1)}
		}
	}
	return KeySwitchKey[T]{Value: kswKey, decompParams: decompParams}
}

// InputLWEDimension returns the input LWEDimension of this key.
func (ksk KeySwitchKey[T]) InputLWEDimension() int {
	return len(ksk.Value)
}

// OutputLWEDimension returns the output LWEDimension of this key.
func (ksk KeySwitchKey[T]) OutputLWEDimension() int {
	return len(ksk.Value[0].Value[0].Value) - 1
}

// Copy returns a copy of the key.
func (ksk KeySwitchKey[T]) Copy() KeySwitchKey[T] {
	return KeySwitchKey[T](GSWCiphertext[T](ksk).Copy())
}

// DecompositionParameters returns the decomposition parameters of the key.
func (ct KeySwitchKey[T]) DecompositionParameters() DecompositionParameters[T] {
	return ct.decompParams
}
