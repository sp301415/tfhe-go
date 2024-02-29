package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// GenEvaluationKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenEvaluationKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenEvaluationKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: e.SingleKeyEncryptor.GenEvaluationKey(),
		CRSPublicKey:  e.GenCRSPublicKey(),
		RelinKey:      e.GenRelinKey(),
	}
}

// GenEvaluationKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *Encryptor[T]) GenEvaluationKeyParallel() EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: e.SingleKeyEncryptor.GenEvaluationKeyParallel(),
		CRSPublicKey:  e.GenCRSPublicKey(),
		RelinKey:      e.GenRelinKey(),
	}
}

// GenKeySwitchKey samples a new keyswitch key skIn -> LWEKey.
//
// This can take a long time.
// Use [*Encryptor.GenKeySwitchKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenKeySwitchKey(skIn tfhe.LWESecretKey[T], gadgetParams tfhe.GadgetParameters[T]) tfhe.KeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKey(skIn, gadgetParams)
}

// GenKeySwitchKeyParallel samples a new keyswitch key skIn -> LWEKey in parallel.
func (e *Encryptor[T]) GenKeySwitchKeyParallel(skIn tfhe.LWESecretKey[T], gadgetParams tfhe.GadgetParameters[T]) tfhe.KeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKeyParallel(skIn, gadgetParams)
}

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenKeySwitchKeyForBootstrapParallel] for better key generation performance.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrap() tfhe.KeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKeyForBootstrap()
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrapParallel() tfhe.KeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKeyForBootstrapParallel()
}

// GenCRSPublicKey samples a new public key from the common reference string.
func (e *Encryptor[T]) GenCRSPublicKey() tfhe.FourierGLevCiphertext[T] {
	e.buffer.ptGLWE.Clear()
	return e.SingleKeyEncryptor.EncryptFourierGLevPlaintext(e.buffer.ptGLWE, e.Parameters.relinKeyParameters)
}

// GenRelinKey samples a new relinearization key.
func (e *Encryptor[T]) GenRelinKey() FourierUniEncryption[T] {
	return e.FourierUniEncryptPlaintext(tfhe.GLWEPlaintext[T]{Value: e.SingleKeyEncryptor.SecretKey.GLWEKey.Value[0]}, e.Parameters.relinKeyParameters)
}
