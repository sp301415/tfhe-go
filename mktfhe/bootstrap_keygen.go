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

// GenKeySwitchKeyForBootstrap samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenKeySwitchKeyForBootstrapParallel] for better key generation performance.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrap() tfhe.LWEKeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKeyForBootstrap()
}

// GenKeySwitchKeyForBootstrapParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor[T]) GenKeySwitchKeyForBootstrapParallel() tfhe.LWEKeySwitchKey[T] {
	return e.SingleKeyEncryptor.GenKeySwitchKeyForBootstrapParallel()
}

// GenCRSPublicKey samples a new public key from the common reference string.
func (e *Encryptor[T]) GenCRSPublicKey() tfhe.FourierGLevCiphertext[T] {
	pk := tfhe.NewFourierGLevCiphertext(e.Parameters.singleKeyParameters, e.Parameters.relinKeyParameters)
	for i := 0; i < e.Parameters.relinKeyParameters.Level(); i++ {
		e.buffer.ctGLWESingle.Value[1].CopyFrom(e.CRS[i])

		e.SingleKeyEncryptor.GaussianSampler.SamplePolyAssign(e.Parameters.GLWEStdDevQ(), e.buffer.ctGLWESingle.Value[0])
		e.SingleKeyEncryptor.PolyEvaluator.ShortFourierPolyMulSubPolyAssign(e.buffer.ctGLWESingle.Value[1], e.SecretKey.FourierGLWEKey.Value[0], e.buffer.ctGLWESingle.Value[0])

		e.SingleKeyEncryptor.ToFourierGLWECiphertextAssign(e.buffer.ctGLWESingle, pk.Value[i])
	}
	return pk
}

// GenRelinKey samples a new relinearization key.
func (e *Encryptor[T]) GenRelinKey() FourierUniEncryption[T] {
	return e.FourierUniEncryptPoly(e.SingleKeyEncryptor.SecretKey.GLWEKey.Value[0], e.Parameters.relinKeyParameters)
}
