package tfhe

// SampleLWEKey samples a new LWE key.
func (e Encrypter[T]) SampleLWEKey() LWEKey[T] {
	sk := NewLWEKey(e.Parameters)
	e.binarySampler.SampleSlice(sk.Value)
	return sk
}

// SampleGLWEKey samples a new GLWE key.
func (e Encrypter[T]) SampleGLWEKey() GLWEKey[T] {
	sk := NewGLWEKey(e.Parameters)
	for i := 0; i < e.Parameters.glweDimension; i++ {
		e.binarySampler.SamplePoly(sk.Value[i])
	}
	return sk
}

// SampleEvaluationKey samples a new evaluation key for bootstrapping.
// This may take a long time, depending on the parameters.

// SampleKeySwitchingKey samples a new keyswitching key skIn -> e.LWEKey.
func (e Encrypter[T]) SampleKeySwitchingKeyFrom(skIn LWEKey[T], decompParams DecompositionParameters[T]) KeySwitchingKey[T] {
	ksk := NewKeySwitchingKey(len(skIn.Value), len(e.lweKey.Value), decompParams)

	for i := 0; i < ksk.InputLWEDimension(); i++ {
		e.EncryptLevInPlace(LWEPlaintext[T]{Value: skIn.Value[i]}, ksk.Value[i])
	}

	return ksk
}

// SampleKeySwitchingKeyForBootstrapping samples a new keyswitching key LWELargeKey -> LWEKey,
// used for bootstrapping.
func (e Encrypter[T]) SampleKeySwitchingKeyForBootstrapping() KeySwitchingKey[T] {
	return e.SampleKeySwitchingKeyFrom(e.lweLargeKey, e.Parameters.pbsParameters)
}
