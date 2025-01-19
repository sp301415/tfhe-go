package tfhe

// EvaluationKey is a public key for Evaluator,
// which consists of BlindRotation Key and KeySwitching Key.
// All keys should be treated as read-only.
// Changing them mid-operation will usually result in wrong results.
type EvaluationKey[T TorusInt] struct {
	// BlindRotateKey is a blindrotate key.
	BlindRotateKey BlindRotateKey[T]
	// KeySwitchKey is a keyswitch key switching LWELargeKey -> LWEKey.
	KeySwitchKey LWEKeySwitchKey[T]
}

// NewEvaluationKey creates a new EvaluationKey.
func NewEvaluationKey[T TorusInt](params Parameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BlindRotateKey: NewBlindRotateKey(params),
		KeySwitchKey:   NewKeySwitchKeyForBootstrap(params),
	}
}

// NewEvaluationKeyCustom creates a new EvaluationKey with custom parameters.
func NewEvaluationKeyCustom[T TorusInt](lweDimension, glweRank, polyDegree int, blindRotateParams, keySwitchParams GadgetParameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		BlindRotateKey: NewBlindRotateKeyCustom(lweDimension, glweRank, polyDegree, blindRotateParams),
		KeySwitchKey:   NewKeySwitchKeyForBootstrapCustom(lweDimension, glweRank, polyDegree, keySwitchParams),
	}
}

// Copy returns a copy of the key.
func (evk EvaluationKey[T]) Copy() EvaluationKey[T] {
	return EvaluationKey[T]{
		BlindRotateKey: evk.BlindRotateKey.Copy(),
		KeySwitchKey:   evk.KeySwitchKey.Copy(),
	}
}

// CopyFrom copies values from key.
func (evk *EvaluationKey[T]) CopyFrom(evkIn EvaluationKey[T]) {
	evk.BlindRotateKey.CopyFrom(evkIn.BlindRotateKey)
	evk.KeySwitchKey.CopyFrom(evkIn.KeySwitchKey)
}

// Clear clears the key.
func (evk *EvaluationKey[T]) Clear() {
	evk.BlindRotateKey.Clear()
	evk.KeySwitchKey.Clear()
}

// BlindRotateKey is a key for blind rotation.
// Essentially, this is a GGSW encryption of LWEKey with GLWEKey.
// However, FFT is already applied for fast external product.
type BlindRotateKey[T TorusInt] struct {
	GadgetParameters GadgetParameters[T]

	// Value has length LWEDimension.
	Value []FourierGGSWCiphertext[T]
}

// NewBlindRotateKey creates a new BlindRotateKey.
func NewBlindRotateKey[T TorusInt](params Parameters[T]) BlindRotateKey[T] {
	brk := make([]FourierGGSWCiphertext[T], params.lweDimension)
	for i := 0; i < params.lweDimension; i++ {
		brk[i] = NewFourierGGSWCiphertext(params, params.blindRotateParameters)
	}
	return BlindRotateKey[T]{Value: brk, GadgetParameters: params.blindRotateParameters}
}

// NewBlindRotateKeyCustom creates a new BlindRotateKey with custom parameters.
func NewBlindRotateKeyCustom[T TorusInt](lweDimension, glweRank, polyDegree int, gadgetParams GadgetParameters[T]) BlindRotateKey[T] {
	brk := make([]FourierGGSWCiphertext[T], lweDimension)
	for i := 0; i < lweDimension; i++ {
		brk[i] = NewFourierGGSWCiphertextCustom(glweRank, polyDegree, gadgetParams)
	}
	return BlindRotateKey[T]{Value: brk, GadgetParameters: gadgetParams}
}

// Copy returns a copy of the key.
func (brk BlindRotateKey[T]) Copy() BlindRotateKey[T] {
	brkCopy := make([]FourierGGSWCiphertext[T], len(brk.Value))
	for i := range brk.Value {
		brkCopy[i] = brk.Value[i].Copy()
	}
	return BlindRotateKey[T]{Value: brkCopy, GadgetParameters: brk.GadgetParameters}
}

// CopyFrom copies values from key.
func (brk *BlindRotateKey[T]) CopyFrom(brkIn BlindRotateKey[T]) {
	for i := range brk.Value {
		brk.Value[i].CopyFrom(brkIn.Value[i])
	}
	brk.GadgetParameters = brkIn.GadgetParameters
}

// Clear clears the key.
func (brk *BlindRotateKey[T]) Clear() {
	for i := range brk.Value {
		brk.Value[i].Clear()
	}
}
