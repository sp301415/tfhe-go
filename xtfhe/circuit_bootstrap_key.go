package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

// CircuitBootstrapKey is a key for Circuit Bootstrapping.
type CircuitBootstrapKey[T tfhe.TorusInt] struct {
	// SchemeSwitchKey is a key for scheme switching.
	// It has length GLWERank,
	// with i-th element being an FFTGGSWCiphertext of i-th secret key.
	SchemeSwitchKey []tfhe.FFTGGSWCiphertext[T]
	// TraceKeys is a map of galois keys used for LWE to GLWE packing.
	TraceKeys map[int]tfhe.GLWEKeySwitchKey[T]
}

// CircuitBootstrapKeyGenerator generates a key for Circuit Bootstrapping.
type CircuitBootstrapKeyGenerator[T tfhe.TorusInt] struct {
	// BFVKeyGenerator is a BFVKeyGenerator for this CircuitBootstrapKeyGenerator.
	*BFVKeyGenerator[T]

	// Params is the parameters for this CircuitBootstrapKeyGenerator.
	Params CircuitBootstrapParameters[T]
}

// NewCircuitBootstrapKeyGenerator creates a new CircuitBootstrapKeyGenerator.
func NewCircuitBootstrapKeyGenerator[T tfhe.TorusInt](params CircuitBootstrapParameters[T], sk tfhe.SecretKey[T]) *CircuitBootstrapKeyGenerator[T] {
	return &CircuitBootstrapKeyGenerator[T]{
		BFVKeyGenerator: NewBFVKeyGenerator(params.Params(), sk),
		Params:          params,
	}
}

// SafeCopy creates a shallow copy of this CircuitBootstrapKeyGenerator.
// Returned CircuitBootstrapKeyGenerator is safe for concurrent use.
func (kg *CircuitBootstrapKeyGenerator[T]) SafeCopy() *CircuitBootstrapKeyGenerator[T] {
	return &CircuitBootstrapKeyGenerator[T]{
		BFVKeyGenerator: kg.BFVKeyGenerator.SafeCopy(),
		Params:          kg.Params,
	}
}

// GenCircuitBootstrapKey generates a key for Circuit Bootstrapping.
func (kg *CircuitBootstrapKeyGenerator[T]) GenCircuitBootstrapKey() CircuitBootstrapKey[T] {
	schemeSwitchKey := make([]tfhe.FFTGGSWCiphertext[T], kg.Params.Params().GLWERank())
	for i := 0; i < kg.Params.Params().GLWERank(); i++ {
		schemeSwitchKey[i] = kg.Encryptor.EncryptFFTGGSWPoly(kg.Encryptor.SecretKey.GLWEKey.Value[i], kg.Params.schemeSwitchParameters)
	}

	return CircuitBootstrapKey[T]{
		SchemeSwitchKey: schemeSwitchKey,
		TraceKeys:       kg.GenGaloisKeysForPack(kg.Params.traceKeySwitchParameters),
	}
}
