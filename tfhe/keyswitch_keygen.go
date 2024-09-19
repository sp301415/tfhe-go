package tfhe

// GenLWEKeySwitchKey samples a new keyswitch key skIn -> LWEKey.
func (e *Encryptor[T]) GenLWEKeySwitchKey(skIn LWESecretKey[T], gadgetParams GadgetParameters[T]) LWEKeySwitchKey[T] {
	ksk := NewLWEKeySwitchKey(e.Parameters, len(skIn.Value), gadgetParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.EncryptLevPlaintextAssign(LWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
	}

	return ksk
}

// GenGLWEKeySwitchKey samples a new keyswitch key skIn -> GLWEKey.
func (e *Encryptor[T]) GenGLWEKeySwitchKey(skIn GLWESecretKey[T], gadgetParams GadgetParameters[T]) GLWEKeySwitchKey[T] {
	ksk := NewGLWEKeySwitchKey(e.Parameters, len(skIn.Value), gadgetParams)

	for i := 0; i < ksk.InputGLWERank(); i++ {
		e.EncryptFourierGLevPlaintextAssign(GLWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
	}

	return ksk
}
