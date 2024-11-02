package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVKeyGenerator generates keyswitching keys for BFV type operations.
//
// BFVKeyGenerator is not safe for concurrent use.
// Use [*BFVKeyGenerator.ShallowCopy] to get a safe copy.
type BFVKeyGenerator[T tfhe.TorusInt] struct {
	// BaseEncryptor is a base encryptor for this BFVKeyGenerator.
	BaseEncryptor *tfhe.Encryptor[T]
	// PolyEvaluator is a PolyEvaluator for this BFVKeyGenerator.
	PolyEvaluator *poly.Evaluator[T]

	// Parameters is a parameter set for this BFVKeyGenerator.
	Parameters tfhe.Parameters[T]

	// KeySwitchParams is a gadget parameter set for keyswitching keys in BFV type operations.
	KeySwitchParams tfhe.GadgetParameters[T]
}

// NewBFVKeyGenerator creates a new BFVKeyGenerator.
func NewBFVKeyGenerator[T tfhe.TorusInt](params tfhe.Parameters[T], keySwitchParams tfhe.GadgetParameters[T], sk tfhe.SecretKey[T]) *BFVKeyGenerator[T] {
	return &BFVKeyGenerator[T]{
		BaseEncryptor:   tfhe.NewEncryptorWithKey(params, sk),
		PolyEvaluator:   poly.NewEvaluator[T](params.PolyDegree()),
		Parameters:      params,
		KeySwitchParams: keySwitchParams,
	}
}

// ShallowCopy creates a shallow copy of this BFVKeyGenerator.
func (kg *BFVKeyGenerator[T]) ShallowCopy() *BFVKeyGenerator[T] {
	return &BFVKeyGenerator[T]{
		BaseEncryptor:   kg.BaseEncryptor.ShallowCopy(),
		PolyEvaluator:   kg.PolyEvaluator.ShallowCopy(),
		Parameters:      kg.Parameters,
		KeySwitchParams: kg.KeySwitchParams,
	}
}

// BFVEvaluationKey is a keyswitching key for BFV type operations.
// It holds relinearization and automorphism keys.
type BFVEvaluationKey[T tfhe.TorusInt] struct {
	// RelinKey is a relinearization key.
	RelinKey tfhe.GLWEKeySwitchKey[T]
	// GaloisKeys is a map of automorphism keys.
	GaloisKeys map[int]tfhe.GLWEKeySwitchKey[T]
}

// GenEvaluationKey generates an evaluation key for BFV type operations.
func (kg *BFVKeyGenerator[T]) GenEvaluationKey(idx []int) BFVEvaluationKey[T] {
	return BFVEvaluationKey[T]{
		RelinKey:   kg.GenRelinKey(),
		GaloisKeys: kg.GenGaloisKeys(idx),
	}
}

// GenRelinKey generates a relinearization key for BFV multiplication.
func (kg *BFVKeyGenerator[T]) GenRelinKey() tfhe.GLWEKeySwitchKey[T] {
	skOut := tfhe.NewGLWESecretKeyCustom[T](kg.Parameters.GLWERank()*(kg.Parameters.GLWERank()+1)/2, kg.Parameters.PolyDegree())
	fskOut := tfhe.NewFourierGLWESecretKeyCustom[T](kg.Parameters.GLWERank()*(kg.Parameters.GLWERank()+1)/2, kg.Parameters.PolyDegree())

	skOutIdx := 0
	for i := 0; i < kg.Parameters.GLWERank(); i++ {
		for j := i; j < kg.Parameters.GLWERank(); j++ {
			kg.BaseEncryptor.PolyEvaluator.MulFourierPolyAssign(kg.BaseEncryptor.SecretKey.FourierGLWEKey.Value[i], kg.BaseEncryptor.SecretKey.FourierGLWEKey.Value[j], fskOut.Value[skOutIdx])
			skOutIdx++
		}
	}

	for i := range fskOut.Value {
		kg.BaseEncryptor.PolyEvaluator.ToPolyAssignUnsafe(fskOut.Value[i], skOut.Value[i])
	}

	return kg.BaseEncryptor.GenGLWEKeySwitchKey(skOut, kg.KeySwitchParams)
}

// GenGaloisKeys generate galois keys for BFV automorphism.
func (kg *BFVKeyGenerator[T]) GenGaloisKeys(idx []int) map[int]tfhe.GLWEKeySwitchKey[T] {
	galKeys := make(map[int]tfhe.GLWEKeySwitchKey[T], len(idx))
	skOut := tfhe.NewGLWESecretKey(kg.Parameters)

	for _, d := range idx {
		for i := 0; i < kg.Parameters.GLWERank(); i++ {
			kg.BaseEncryptor.PolyEvaluator.PermutePolyAssign(kg.BaseEncryptor.SecretKey.GLWEKey.Value[i], d, skOut.Value[i])
		}
		galKeys[d] = kg.BaseEncryptor.GenGLWEKeySwitchKey(skOut, kg.KeySwitchParams)
	}
	return galKeys
}

// GenGaloisKeysAssign generates automorphism keys for BFV automorphism and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysAssign(idx []int, galKeysOut map[int]tfhe.GLWEKeySwitchKey[T]) {
	skOut := tfhe.NewGLWESecretKey(kg.Parameters)

	for _, d := range idx {
		for i := 0; i < kg.Parameters.GLWERank(); i++ {
			kg.BaseEncryptor.PolyEvaluator.PermutePolyAssign(kg.BaseEncryptor.SecretKey.GLWEKey.Value[i], d, skOut.Value[i])
		}
		galKeysOut[d] = kg.BaseEncryptor.GenGLWEKeySwitchKey(skOut, kg.KeySwitchParams)
	}
}

// GenGaloisKeysForLWEToGLWECiphertext generates automorphism keys for BFV automorphism for LWE to GLWE packing.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForLWEToGLWECiphertext() map[int]tfhe.GLWEKeySwitchKey[T] {
	auts := make([]int, kg.Parameters.LogPolyDegree())
	for i := range auts {
		auts[i] = 1<<(kg.Parameters.LogPolyDegree()-i) + 1
	}
	return kg.GenGaloisKeys(auts)
}

// GenGaloisKeysForLWEToGLWECiphertextAssign generates automorphism keys for BFV automorphism for LWE to GLWE packing and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForLWEToGLWECiphertextAssign(galKeysOut map[int]tfhe.GLWEKeySwitchKey[T]) {
	auts := make([]int, kg.Parameters.LogPolyDegree())
	for i := range auts {
		auts[i] = 1<<(kg.Parameters.LogPolyDegree()-i) + 1
	}
	kg.GenGaloisKeysAssign(auts, galKeysOut)
}
