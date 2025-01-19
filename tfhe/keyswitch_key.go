package tfhe

// LWEKeySwitchKey is a LWE keyswitch key from one LWEKey to another LWEKey.
type LWEKeySwitchKey[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length InputLWEDimension.
	Value []LevCiphertext[T]
}

// NewLWEKeySwitchKey creates a new LWEKeySwitchingKey.
func NewLWEKeySwitchKey[T TorusInt](params Parameters[T], inputDimension int, gadgetParams GadgetParameters[T]) LWEKeySwitchKey[T] {
	ksk := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		ksk[i] = NewLevCiphertext(params, gadgetParams)
	}
	return LWEKeySwitchKey[T]{Value: ksk, GadgetParameters: gadgetParams}
}

// NewLWEKeySwitchKeyCustom creates a new LWEKeySwitchingKey with custom parameters.
func NewLWEKeySwitchKeyCustom[T TorusInt](inputDimension, outputDimension int, gadgetParams GadgetParameters[T]) LWEKeySwitchKey[T] {
	ksk := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		ksk[i] = NewLevCiphertextCustom(outputDimension, gadgetParams)
	}
	return LWEKeySwitchKey[T]{Value: ksk, GadgetParameters: gadgetParams}
}

// NewKeySwitchKeyForBootstrap creates a new LWEKeySwitchingKey for bootstrapping.
func NewKeySwitchKeyForBootstrap[T TorusInt](params Parameters[T]) LWEKeySwitchKey[T] {
	return NewLWEKeySwitchKeyCustom(params.glweDimension-params.lweDimension, params.lweDimension, params.keySwitchParameters)
}

// NewKeySwitchKeyForBootstrapCustom creates a new LWEKeySwitchingKey with custom parameters.
func NewKeySwitchKeyForBootstrapCustom[T TorusInt](lweDimension, glweRank, polyDegree int, gadgetParams GadgetParameters[T]) LWEKeySwitchKey[T] {
	return NewLWEKeySwitchKeyCustom(glweRank*polyDegree-lweDimension, lweDimension, gadgetParams)
}

// InputLWEDimension returns the input LWEDimension of this key.
func (ksk LWEKeySwitchKey[T]) InputLWEDimension() int {
	return len(ksk.Value)
}

// Copy returns a copy of the key.
func (ksk LWEKeySwitchKey[T]) Copy() LWEKeySwitchKey[T] {
	kskCopy := make([]LevCiphertext[T], len(ksk.Value))
	for i := range ksk.Value {
		kskCopy[i] = ksk.Value[i].Copy()
	}
	return LWEKeySwitchKey[T]{Value: kskCopy, GadgetParameters: ksk.GadgetParameters}
}

// CopyFrom copies values from key.
func (ksk *LWEKeySwitchKey[T]) CopyFrom(kskIn LWEKeySwitchKey[T]) {
	for i := range ksk.Value {
		ksk.Value[i].CopyFrom(kskIn.Value[i])
	}
	ksk.GadgetParameters = kskIn.GadgetParameters
}

// Clear clears the key.
func (ksk *LWEKeySwitchKey[T]) Clear() {
	for i := range ksk.Value {
		ksk.Value[i].Clear()
	}
}

// GLWEKeySwitchKey is a GLWE keyswitch key from one GLWEKey to another GLWEKey.
type GLWEKeySwitchKey[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length InputGLWERank.
	Value []FourierGLevCiphertext[T]
}

// NewGLWEKeySwitchKey creates a new GLWEKeySwitchingKey.
func NewGLWEKeySwitchKey[T TorusInt](params Parameters[T], inputGLWERank int, gadgetParams GadgetParameters[T]) GLWEKeySwitchKey[T] {
	ksk := make([]FourierGLevCiphertext[T], inputGLWERank)
	for i := 0; i < inputGLWERank; i++ {
		ksk[i] = NewFourierGLevCiphertext(params, gadgetParams)
	}
	return GLWEKeySwitchKey[T]{Value: ksk, GadgetParameters: gadgetParams}
}

// NewGLWEKeySwitchKeyCustom creates a new GLWEKeySwitchingKey with custom parameters.
func NewGLWEKeySwitchKeyCustom[T TorusInt](inputGLWERank, outputGLWERank, polyDegree int, gadgetParams GadgetParameters[T]) GLWEKeySwitchKey[T] {
	ksk := make([]FourierGLevCiphertext[T], inputGLWERank)
	for i := 0; i < inputGLWERank; i++ {
		ksk[i] = NewFourierGLevCiphertextCustom(outputGLWERank, polyDegree, gadgetParams)
	}
	return GLWEKeySwitchKey[T]{Value: ksk, GadgetParameters: gadgetParams}
}

// InputGLWERank returns the input GLWERank of this key.
func (ksk GLWEKeySwitchKey[T]) InputGLWERank() int {
	return len(ksk.Value)
}

// Copy returns a copy of the key.
func (ksk GLWEKeySwitchKey[T]) Copy() GLWEKeySwitchKey[T] {
	kskCopy := make([]FourierGLevCiphertext[T], len(ksk.Value))
	for i := range ksk.Value {
		kskCopy[i] = ksk.Value[i].Copy()
	}
	return GLWEKeySwitchKey[T]{Value: kskCopy, GadgetParameters: ksk.GadgetParameters}
}

// CopyFrom copies values from key.
func (ksk *GLWEKeySwitchKey[T]) CopyFrom(kskIn GLWEKeySwitchKey[T]) {
	for i := range ksk.Value {
		ksk.Value[i].CopyFrom(kskIn.Value[i])
	}
	ksk.GadgetParameters = kskIn.GadgetParameters
}

// Clear clears the key.
func (ksk *GLWEKeySwitchKey[T]) Clear() {
	for i := range ksk.Value {
		ksk.Value[i].Clear()
	}
}
