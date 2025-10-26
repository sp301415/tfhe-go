package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

// EvaluationKey is a multi-key variant of [tfhe.EvaluationKey].
type EvaluationKey[T tfhe.TorusInt] struct {
	// EvaluationKey is an embedded single-key EvaluationKey.
	tfhe.EvaluationKey[T]
	// CRSPublicKey is a public key from the common reference string.
	CRSPublicKey tfhe.FFTGLevCiphertext[T]
	// RelinKey is a relinearization key.
	RelinKey FFTUniEncryption[T]
}

// NewEvaluationKey creates a new EvaluationKey.
func NewEvaluationKey[T tfhe.TorusInt](params Parameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: tfhe.NewEvaluationKey(params.subParams),
		CRSPublicKey:  tfhe.NewFFTGLevCiphertext(params.subParams, params.relinKeyParams),
		RelinKey:      NewFFTUniEncryption(params, params.relinKeyParams),
	}
}

// NewEvaluationKeyCustom creates a new EvaluationKey with custom parameters.
func NewEvaluationKeyCustom[T tfhe.TorusInt](lweDimension, polyRank int, blindRotateParams, keySwitchParams, relinParams tfhe.GadgetParameters[T]) EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: tfhe.NewEvaluationKeyCustom(lweDimension, 1, polyRank, blindRotateParams, keySwitchParams),
		CRSPublicKey:  tfhe.NewFFTGLevCiphertextCustom(1, polyRank, relinParams),
		RelinKey:      NewFFTUniEncryptionCustom(polyRank, relinParams),
	}
}

// Copy returns a copy of the key.
func (evk EvaluationKey[T]) Copy() EvaluationKey[T] {
	return EvaluationKey[T]{
		EvaluationKey: evk.EvaluationKey.Copy(),
		CRSPublicKey:  evk.CRSPublicKey.Copy(),
		RelinKey:      evk.RelinKey.Copy(),
	}
}

// CopyFrom copies values from key.
func (evk *EvaluationKey[T]) CopyFrom(evkIn EvaluationKey[T]) {
	evk.EvaluationKey.CopyFrom(evkIn.EvaluationKey)
	evk.CRSPublicKey.CopyFrom(evkIn.CRSPublicKey)
	evk.RelinKey.CopyFrom(evkIn.RelinKey)
}

// Clear clears the key.
func (evk *EvaluationKey[T]) Clear() {
	evk.EvaluationKey.Clear()
	evk.CRSPublicKey.Clear()
	evk.RelinKey.Clear()
}
