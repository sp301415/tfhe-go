package tfhe

// EvaluationKey is a public key for Evaluator,
// which consists of Bootstrapping Key and KeySwitching Key.
// All keys should be treated as read-only.
// Changing them mid-operation will usually result in wrong results.
type EvaluationKey[T TorusInt] struct {
	// BootstrapKey is a bootstrap key.
	BootstrapKey BootstrapKey[T]
	// KeySwitchKey is a keyswitch key switching LWELargeKey -> LWEKey.
	KeySwitchKey LWEKeySwitchKey[T]
}

// NewEvaluationKey allocates an empty EvaluationKey.
func NewEvaluationKey[T TorusInt](params Parameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: NewBootstrapKey(params),
		KeySwitchKey: NewKeySwitchKeyForBootstrap(params),
	}
}

// NewEvaluationKeyCustom allocates an empty EvaluationKey with custom parameters.
func NewEvaluationKeyCustom[T TorusInt](lweDimension, glweRank, polyDegree int, bootstrapParams, keyswitchParams GadgetParameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BootstrapKey: NewBootstrapKeyCustom(lweDimension, glweRank, polyDegree, bootstrapParams),
		KeySwitchKey: NewKeySwitchKeyForBootstrapCustom(lweDimension, glweRank, polyDegree, keyswitchParams),
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
func NewBootstrapKeyCustom[T TorusInt](lweDimension, glweRank, polyDegree int, gadgetParams GadgetParameters[T]) BootstrapKey[T] {
	bsk := make([]FourierGGSWCiphertext[T], lweDimension)
	for i := 0; i < lweDimension; i++ {
		bsk[i] = NewFourierGGSWCiphertextCustom(glweRank, polyDegree, gadgetParams)
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
