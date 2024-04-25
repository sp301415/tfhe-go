package tfhe

// EvaluationKey is a public key for Evaluator,
// which consists of Bootstrapping Key and KeySwitching Key.
// All keys should be treated as read-only.
// Changing them mid-operation will usually result in wrong results.
type EvaluationKey[T TorusInt] struct {
	// BootstrapKey is a bootstrap key.
	BootstrapKey BootstrapKey[T]
	// KeySwitchKey is a keyswitch key switching LWELargeKey -> LWEKey.
	KeySwitchKey KeySwitchKey[T]
}

// NewEvaluationKey allocates an empty EvaluationKey.
func NewEvaluationKey[T TorusInt](params Parameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: NewBootstrapKey(params),
		KeySwitchKey: NewKeySwitchKeyForBootstrap(params),
	}
}

// NewEvaluationKeyCustom allocates an empty EvaluationKey with custom parameters.
func NewEvaluationKeyCustom[T TorusInt](lweDimension, glweDimension, polyDegree int, bootstrapParams, keyswitchParams GadgetParameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: NewBootstrapKeyCustom(lweDimension, glweDimension, polyDegree, bootstrapParams),
		KeySwitchKey: NewKeySwitchKeyForBootstrapCustom(lweDimension, glweDimension, polyDegree, keyswitchParams),
	}
}

// Copy returns a copy of the key.
func (evk EvaluationKey[T]) Copy() EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: evk.BootstrapKey.Copy(),
		KeySwitchKey: evk.KeySwitchKey.Copy(),
	}
}

// CopyFrom copies values from key.
func (evk *EvaluationKey[T]) CopyFrom(evkIn EvaluationKey[T]) {
	evk.BootstrapKey.CopyFrom(evkIn.BootstrapKey)
	evk.KeySwitchKey.CopyFrom(evkIn.KeySwitchKey)
}

// Clear clears the key.
func (evk *EvaluationKey[T]) Clear() {
	evk.BootstrapKey.Clear()
	evk.KeySwitchKey.Clear()
}

// BootstrapKey is a key for bootstrapping.
// Essentially, this is a GGSW encryption of LWEKey with GLWEKey.
// However, FFT is already applied for fast external product.
type BootstrapKey[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length LWEDimension.
	Value []FourierGGSWCiphertext[T]
}

// NewBootstrapKey allocates an empty BootstrappingKey.
func NewBootstrapKey[T TorusInt](params Parameters[T]) BootstrapKey[T] {
	bsk := make([]FourierGGSWCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		bsk[i] = NewFourierGGSWCiphertext(params, params.bootstrapParameters)
	}
	return BootstrapKey[T]{Value: bsk, GadgetParameters: params.bootstrapParameters}
}

// NewBootstrapKeyCustom allocates an empty BootstrappingKey with custom parameters.
func NewBootstrapKeyCustom[T TorusInt](lweDimension, glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) BootstrapKey[T] {
	bsk := make([]FourierGGSWCiphertext[T], lweDimension)
	for i := 0; i < lweDimension; i++ {
		bsk[i] = NewFourierGGSWCiphertextCustom[T](glweDimension, polyDegree, gadgetParams)
	}
	return BootstrapKey[T]{Value: bsk, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the key.
func (bsk BootstrapKey[T]) Copy() BootstrapKey[T] {
	bskCopy := make([]FourierGGSWCiphertext[T], len(bsk.Value))
	for i := range bsk.Value {
		bskCopy[i] = bsk.Value[i].Copy()
	}
	return BootstrapKey[T]{Value: bskCopy, GadgetParameters: bsk.GadgetParameters}
}

// CopyFrom copies values from key.
func (bsk *BootstrapKey[T]) CopyFrom(bskIn BootstrapKey[T]) {
	for i := range bsk.Value {
		bsk.Value[i].CopyFrom(bskIn.Value[i])
	}
	bsk.GadgetParameters = bskIn.GadgetParameters
}

// Clear clears the key.
func (bsk *BootstrapKey[T]) Clear() {
	for i := range bsk.Value {
		bsk.Value[i].Clear()
	}
}

// KeySwitchKey is a LWE keyswitch key from one LWEKey to another LWEKey.
type KeySwitchKey[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length InputLWEDimension.
	Value []LevCiphertext[T]
}

// NewKeySwitchKey allocates an empty KeySwitchingKey.
func NewKeySwitchKey[T TorusInt](inputDimension, outputDimension int, gadgetParams GadgetParameters[T]) KeySwitchKey[T] {
	ksk := make([]LevCiphertext[T], inputDimension)
	for i := 0; i < inputDimension; i++ {
		ksk[i] = NewLevCiphertextCustom(outputDimension, gadgetParams)
	}
	return KeySwitchKey[T]{Value: ksk, GadgetParameters: gadgetParams}
}

// NewKeySwitchKeyForBootstrap allocates an empty KeySwitchingKey for bootstrapping.
func NewKeySwitchKeyForBootstrap[T TorusInt](params Parameters[T]) KeySwitchKey[T] {
	return NewKeySwitchKey[T](params.lweLargeDimension-params.lweDimension, params.lweDimension, params.keyswitchParameters)
}

// NewKeySwitchKeyForBootstrapCustom allocates an empty KeySwitchingKey with custom parameters.
func NewKeySwitchKeyForBootstrapCustom[T TorusInt](lweDimension, glweDimension, polyDegree int, gadgetParams GadgetParameters[T]) KeySwitchKey[T] {
	return NewKeySwitchKey[T](glweDimension*polyDegree-lweDimension, lweDimension, gadgetParams)
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
	kskCopy := make([]LevCiphertext[T], len(ksk.Value))
	for i := range ksk.Value {
		kskCopy[i] = ksk.Value[i].Copy()
	}
	return KeySwitchKey[T]{Value: kskCopy, GadgetParameters: ksk.GadgetParameters}
}

// CopyFrom copies values from key.
func (ksk *KeySwitchKey[T]) CopyFrom(kskIn KeySwitchKey[T]) {
	for i := range ksk.Value {
		ksk.Value[i].CopyFrom(kskIn.Value[i])
	}
	ksk.GadgetParameters = kskIn.GadgetParameters
}

// Clear clears the key.
func (ksk *KeySwitchKey[T]) Clear() {
	for i := range ksk.Value {
		ksk.Value[i].Clear()
	}
}
