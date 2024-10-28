package xtfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// BFVKeyGenerator generates keyswitching keys for BFV type operations.
// Only parameters with GLWERank = 1 are supported.
//
// BFVKeyGenerator is not safe for concurrent use.
// Use [*BFVKeyGenerator.ShallowCopy] to get a safe copy.
type BFVKeyGenerator[T tfhe.TorusInt] struct {
	// BaseEncryptor is a base encryptor for this BFVKeyGenerator.
	BaseEncryptor *tfhe.Encryptor[T]

	// KeySwitchParams is a gadget parameter set for keyswitching keys in BFV type operations.
	KeySwitchParams tfhe.GadgetParameters[T]

	buffer bfvKeyGenerationBuffer[T]
}

// bfvKeyGenerationBuffer is a buffer for BFV type key generation.
type bfvKeyGenerationBuffer[T tfhe.TorusInt] struct {
	// sk is a buffer for transformed secret key.
	sk tfhe.GLWESecretKey[T]
	// fptSk is a buffer for the fourier transformed sk.
	fsk poly.FourierPoly
}

// NewBFVKeyGenerator creates a new BFVKeyGenerator.
//
// Panics when GLWERank > 1.
func NewBFVKeyGenerator[T tfhe.TorusInt](params tfhe.Parameters[T], keySwitchParams tfhe.GadgetParameters[T], sk tfhe.SecretKey[T]) *BFVKeyGenerator[T] {
	if params.GLWERank() > 1 {
		panic("BFVKeyGenerator only supports GLWERank = 1")
	}

	return &BFVKeyGenerator[T]{
		BaseEncryptor:   tfhe.NewEncryptorWithKey(params, sk),
		KeySwitchParams: keySwitchParams,
		buffer:          newKeyGenerationBuffer(params),
	}
}

// newKeyGenerationBuffer creates a new keyGenerationBuffer.
func newKeyGenerationBuffer[T tfhe.TorusInt](params tfhe.Parameters[T]) bfvKeyGenerationBuffer[T] {
	return bfvKeyGenerationBuffer[T]{
		sk:  tfhe.NewGLWESecretKey(params),
		fsk: poly.NewFourierPoly(params.PolyDegree()),
	}
}

// ShallowCopy creates a shallow copy of this BFVKeyGenerator.
func (kg *BFVKeyGenerator[T]) ShallowCopy() *BFVKeyGenerator[T] {
	return &BFVKeyGenerator[T]{
		BaseEncryptor:   kg.BaseEncryptor.ShallowCopy(),
		KeySwitchParams: kg.KeySwitchParams,
		buffer:          newKeyGenerationBuffer(kg.BaseEncryptor.Parameters),
	}
}

// BFVKeySwitchKey is a keyswitching key for BFV type operations.
// It holds relinearization and automorphism keys.
type BFVKeySwitchKey[T tfhe.TorusInt] struct {
	// RelinKey is a relinearization key.
	RelinKey tfhe.GLWEKeySwitchKey[T]
	// GaloisKeys is a map of automorphism keys.
	GaloisKeys map[int]tfhe.GLWEKeySwitchKey[T]
}

// GenRelinKey generates a relinearization key for BFV multiplication.
func (kg *BFVKeyGenerator[T]) GenRelinKey() tfhe.GLWEKeySwitchKey[T] {
	fsk := kg.BaseEncryptor.SecretKey.FourierGLWEKey.Value[0]
	kg.BaseEncryptor.PolyEvaluator.MulFourierPolyAssign(fsk, fsk, kg.buffer.fsk)
	kg.BaseEncryptor.PolyEvaluator.ToPolyAssignUnsafe(kg.buffer.fsk, kg.buffer.sk.Value[0])

	return kg.BaseEncryptor.GenGLWEKeySwitchKey(kg.buffer.sk, kg.KeySwitchParams)
}

// GenGaloisKeys generate galois keys for BFV automorphism.
func (kg *BFVKeyGenerator[T]) GenGaloisKeys(idx []int) map[int]tfhe.GLWEKeySwitchKey[T] {
	galKeys := make(map[int]tfhe.GLWEKeySwitchKey[T], len(idx))
	sk := kg.BaseEncryptor.SecretKey.GLWEKey.Value[0]

	for _, d := range idx {
		kg.BaseEncryptor.PolyEvaluator.PermutePolyAssign(sk, d, kg.buffer.sk.Value[0])
		galKeys[d] = kg.BaseEncryptor.GenGLWEKeySwitchKey(kg.buffer.sk, kg.KeySwitchParams)
	}
	return galKeys
}

// GenGaloisKeysAssign generates automorphism keys for BFV automorphism and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysAssign(idx []int, galKeysOut map[int]tfhe.GLWEKeySwitchKey[T]) {
	sk := kg.BaseEncryptor.SecretKey.GLWEKey.Value[0]

	for _, d := range idx {
		kg.BaseEncryptor.PolyEvaluator.PermutePolyAssign(sk, d, kg.buffer.sk.Value[0])
		galKeysOut[d] = kg.BaseEncryptor.GenGLWEKeySwitchKey(kg.buffer.sk, kg.KeySwitchParams)
	}
}

// GenGaloisKeysForRingPack generates automorphism keys for BFV automorphism for LWE to RLWE packing.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForRingPack() map[int]tfhe.GLWEKeySwitchKey[T] {
	auts := make([]int, kg.BaseEncryptor.Parameters.LogPolyDegree())
	for i := range auts {
		auts[i] = 1<<(kg.BaseEncryptor.Parameters.LogPolyDegree()-i) + 1
	}
	return kg.GenGaloisKeys(auts)
}

// GenGaloisKeysForRingPackAssign generates automorphism keys for BFV automorphism for LWE to RLWE packing and assigns them to the given map.
// If a key for a given automorphism degree already exists in the map, it will be overwritten.
func (kg *BFVKeyGenerator[T]) GenGaloisKeysForRingPackAssign(galKeysOut map[int]tfhe.GLWEKeySwitchKey[T]) {
	auts := make([]int, kg.BaseEncryptor.Parameters.LogPolyDegree())
	for i := range auts {
		auts[i] = 1<<(kg.BaseEncryptor.Parameters.LogPolyDegree()-i) + 1
	}
	kg.GenGaloisKeysAssign(auts, galKeysOut)
}
