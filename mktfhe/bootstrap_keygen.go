package mktfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// GenEvalKey samples a new evaluation key for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenEvalKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenEvalKey() EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: e.SubEncryptor.GenEvalKey(),
		CRSPublicKey:  e.GenCRSPublicKey(),
		RelinKey:      e.GenRelinKey(),
	}
}

// GenEvalKeyParallel samples a new evaluation key for bootstrapping in parallel.
func (e *Encryptor[T]) GenEvalKeyParallel() EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: e.SubEncryptor.GenEvalKeyParallel(),
		CRSPublicKey:  e.GenCRSPublicKey(),
		RelinKey:      e.GenRelinKey(),
	}
}

// GenDefaultKeySwitchKey samples a new keyswitch key LWELargeKey -> LWEKey,
// used for bootstrapping.
//
// This can take a long time.
// Use [*Encryptor.GenDefaultKeySwitchKeyParallel] for better key generation performance.
func (e *Encryptor[T]) GenDefaultKeySwitchKey() tfhe.LWEKeySwitchKey[T] {
	return e.SubEncryptor.GenDefaultKeySwitchKey()
}

// GenDefaultKeySwitchKeyParallel samples a new keyswitch key LWELargeKey -> LWEKey in parallel,
// used for bootstrapping.
func (e *Encryptor[T]) GenDefaultKeySwitchKeyParallel() tfhe.LWEKeySwitchKey[T] {
	return e.SubEncryptor.GenDefaultKeySwitchKeyParallel()
}

// GenCRSPublicKey samples a new public key from the common reference string.
func (e *Encryptor[T]) GenCRSPublicKey() tfhe.FFTGLevCiphertext[T] {
	pk := tfhe.NewFFTGLevCiphertext(e.Params.subParams, e.Params.relinKeyParams)
	for i := 0; i < e.Params.relinKeyParams.Level(); i++ {
		e.buf.ctSubGLWE.Value[1].CopyFrom(e.CRS[i])

		e.SubEncryptor.GaussianSampler.SamplePolyTo(e.buf.ctSubGLWE.Value[0], e.Params.GLWEStdDevQ())
		e.SubEncryptor.PolyEvaluator.ShortFFTPolyMulSubPolyTo(e.buf.ctSubGLWE.Value[0], e.buf.ctSubGLWE.Value[1], e.SecretKey.FFTGLWEKey.Value[0])

		e.SubEncryptor.FFTGLWECiphertextTo(pk.Value[i], e.buf.ctSubGLWE)
	}
	return pk
}

// GenRelinKey samples a new relinearization key.
func (e *Encryptor[T]) GenRelinKey() FFTUniEncryption[T] {
	return e.FFTUniEncryptPoly(e.SubEncryptor.SecretKey.GLWEKey.Value[0], e.Params.relinKeyParams)
}
