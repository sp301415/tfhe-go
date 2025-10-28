package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVEvaluationKey is a keyswitching key for BFV type operations.
// It holds relinearization and automorphism keys.
type BFVEvaluationKey[T tfhe.TorusInt] struct {
	// RelinKey is a relinearization key.
	RelinKey tfhe.GLWEKeySwitchKey[T]
	// GaloisKeys is a map of automorphism keys.
	GaloisKeys map[int]tfhe.GLWEKeySwitchKey[T]
}

// BFVKeyGenerator generates keyswitching keys for BFV type operations.
//
// BFVKeyGenerator is not safe for concurrent use.
// Use [*BFVKeyGenerator.SafeCopy] to get a safe copy.
type BFVKeyGenerator[T tfhe.TorusInt] struct {
	// Encryptor is a base encryptor for this BFVKeyGenerator.
	Encryptor *tfhe.Encryptor[T]
	// PolyEvaluator is a PolyEvaluator for this BFVKeyGenerator.
	PolyEvaluator *poly.Evaluator[T]

	// Params is the parameters for this BFVKeyGenerator.
	Params tfhe.Parameters[T]
}

// NewBFVKeyGenerator creates a new BFVKeyGenerator.
func NewBFVKeyGenerator[T tfhe.TorusInt](params tfhe.Parameters[T], sk tfhe.SecretKey[T]) *BFVKeyGenerator[T] {
	return &BFVKeyGenerator[T]{
		Encryptor:     tfhe.NewEncryptorWithKey(params, sk),
		PolyEvaluator: poly.NewEvaluator[T](params.PolyRank()),
		Params:        params,
	}
}

// SafeCopy creates a shallow copy of this BFVKeyGenerator.
func (kg *BFVKeyGenerator[T]) SafeCopy() *BFVKeyGenerator[T] {
	return &BFVKeyGenerator[T]{
		Encryptor:     kg.Encryptor.SafeCopy(),
		PolyEvaluator: kg.PolyEvaluator.SafeCopy(),
		Params:        kg.Params,
	}
}

// GenEvalKey generates an evaluation key for BFV type operations.
func (kg *BFVKeyGenerator[T]) GenEvalKey(idx []int, kskParams tfhe.GadgetParameters[T]) BFVEvaluationKey[T] {
	return BFVEvaluationKey[T]{
		RelinKey:   kg.GenRelinKey(kskParams),
		GaloisKeys: kg.GenGaloisKeys(idx, kskParams),
	}
}

// GenRelinKey generates a relinearization key for BFV multiplication.
func (kg *BFVKeyGenerator[T]) GenRelinKey(kskParams tfhe.GadgetParameters[T]) tfhe.GLWEKeySwitchKey[T] {
	rlkRank := kg.Params.GLWERank() * (kg.Params.GLWERank() + 1) / 2
	skOut := tfhe.NewGLWESecretKeyCustom[T](rlkRank, kg.Params.PolyRank())
	fskOut := tfhe.NewFFTGLWESecretKeyCustom[T](rlkRank, kg.Params.PolyRank())

	skOutIdx := 0
	for i := 0; i < kg.Params.GLWERank(); i++ {
		for j := i; j < kg.Params.GLWERank(); j++ {
			kg.Encryptor.PolyEvaluator.MulFFTPolyTo(fskOut.Value[skOutIdx], kg.Encryptor.SecretKey.FFTGLWEKey.Value[i], kg.Encryptor.SecretKey.FFTGLWEKey.Value[j])
			skOutIdx++
		}
	}

	for i := range fskOut.Value {
		kg.Encryptor.PolyEvaluator.InvFFTToUnsafe(skOut.Value[i], fskOut.Value[i])
	}

	return kg.Encryptor.GenGLWEKeySwitchKey(skOut, kskParams)
}

// GenGaloisKeys generate galois keys for BFV automorphism.
func (kg *BFVKeyGenerator[T]) GenGaloisKeys(idx []int, kskParams tfhe.GadgetParameters[T]) map[int]tfhe.GLWEKeySwitchKey[T] {
	galKeys := make(map[int]tfhe.GLWEKeySwitchKey[T], len(idx))
	skOut := tfhe.NewGLWESecretKey(kg.Params)

	for _, d := range idx {
		for i := 0; i < kg.Params.GLWERank(); i++ {
			kg.Encryptor.PolyEvaluator.PermutePolyTo(skOut.Value[i], kg.Encryptor.SecretKey.GLWEKey.Value[i], d)
		}
		galKeys[d] = kg.Encryptor.GenGLWEKeySwitchKey(skOut, kskParams)
	}
	return galKeys
}

// GenGaloisKeysTo generates automorphism keys for BFV automorphism and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysTo(galKeysOut map[int]tfhe.GLWEKeySwitchKey[T], idx []int, kskParams tfhe.GadgetParameters[T]) {
	skOut := tfhe.NewGLWESecretKey(kg.Params)

	for _, d := range idx {
		for i := 0; i < kg.Params.GLWERank(); i++ {
			kg.Encryptor.PolyEvaluator.PermutePolyTo(skOut.Value[i], kg.Encryptor.SecretKey.GLWEKey.Value[i], d)
		}
		galKeysOut[d] = kg.Encryptor.GenGLWEKeySwitchKey(skOut, kskParams)
	}
}

// GenGaloisKeysForPack generates automorphism keys for BFV automorphism for LWE to GLWE packing.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForPack(kskParams tfhe.GadgetParameters[T]) map[int]tfhe.GLWEKeySwitchKey[T] {
	auts := make([]int, kg.Params.LogPolyRank())
	for i := range auts {
		auts[i] = 1<<(kg.Params.LogPolyRank()-i) + 1
	}
	return kg.GenGaloisKeys(auts, kskParams)
}

// GenGaloisKeysForPackTo generates automorphism keys for BFV automorphism for LWE to GLWE packing and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForPackTo(galKeysOut map[int]tfhe.GLWEKeySwitchKey[T], kskParams tfhe.GadgetParameters[T]) {
	auts := make([]int, kg.Params.LogPolyRank())
	for i := range auts {
		auts[i] = 1<<(kg.Params.LogPolyRank()-i) + 1
	}
	kg.GenGaloisKeysTo(galKeysOut, auts, kskParams)
}
