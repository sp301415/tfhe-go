package tfhe

// GenLWEKeySwitchKey samples a new keyswitch key skIn -> LWEKey.
func (e *Encryptor[T]) GenLWEKeySwitchKey(skIn LWESecretKey[T], gadgetParams GadgetParameters[T]) LWEKeySwitchKey[T] {
	ksk := NewLWEKeySwitchKey(e.Params, len(skIn.Value), gadgetParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.EncryptLevScalarTo(ksk.Value[i], skIn.Value[i])
	}

	return ksk
}

// GenGLWEKeySwitchKey samples a new keyswitch key skIn -> GLWEKey.
func (e *Encryptor[T]) GenGLWEKeySwitchKey(skIn GLWESecretKey[T], gadgetParams GadgetParameters[T]) GLWEKeySwitchKey[T] {
	ksk := NewGLWEKeySwitchKey(e.Params, len(skIn.Value), gadgetParams)

	for i := 0; i < ksk.InputGLWERank(); i++ {
		e.EncryptFFTGLevPolyTo(ksk.Value[i], skIn.Value[i])
	}

	return ksk
}
