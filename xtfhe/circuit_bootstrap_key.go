package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

// CircuitBootstrapKey is a key for Circuit Bootstrapping.
type CircuitBootstrapKey[T tfhe.TorusInt] struct {
	// SchemeSwitchKey is a key for scheme switching.
	// It has length GLWERank,
	// with i-th element being an FourierGGSWCiphertext of i-th secret key.
	SchemeSwitchKey []tfhe.FourierGGSWCiphertext[T]
	// TraceKeys is a map of galois keys used for LWE to GLWE packing.
	TraceKeys map[int]tfhe.GLWEKeySwitchKey[T]
}

// CircuitBootstrapKeyGenerator generates a key for Circuit Bootstrapping.
type CircuitBootstrapKeyGenerator[T tfhe.TorusInt] struct {
	// BFVKeyGenerator is a BFVKeyGenerator for this CircuitBootstrapKeyGenerator.
	*BFVKeyGenerator[T]

	// Parameters is a parameter set for this CircuitBootstrapKeyGenerator.
	Parameters CircuitBootstrapParameters[T]
}

// NewCircuitBootstrapKeyGenerator creates a new CircuitBootstrapKeyGenerator.
func NewCircuitBootstrapKeyGenerator[T tfhe.TorusInt](params CircuitBootstrapParameters[T], sk tfhe.SecretKey[T]) *CircuitBootstrapKeyGenerator[T] {
	return &CircuitBootstrapKeyGenerator[T]{
		BFVKeyGenerator: NewBFVKeyGenerator(params.BaseParameters(), sk),
		Parameters:      params,
	}
}

// ShallowCopy creates a shallow copy of this CircuitBootstrapKeyGenerator.
// Returned CircuitBootstrapKeyGenerator is safe for concurrent use.
func (kg *CircuitBootstrapKeyGenerator[T]) ShallowCopy() *CircuitBootstrapKeyGenerator[T] {
	return &CircuitBootstrapKeyGenerator[T]{
		BFVKeyGenerator: kg.BFVKeyGenerator.ShallowCopy(),
		Parameters:      kg.Parameters,
	}
}

// GenCircuitBootstrapKey generates a key for Circuit Bootstrapping.
func (kg *CircuitBootstrapKeyGenerator[T]) GenCircuitBootstrapKey() CircuitBootstrapKey[T] {
	schemeSwitchKey := make([]tfhe.FourierGGSWCiphertext[T], kg.Parameters.BaseParameters().GLWERank())
	for i := 0; i < kg.Parameters.BaseParameters().GLWERank(); i++ {
		schemeSwitchKey[i] = kg.BaseEncryptor.EncryptFourierGGSWPlaintext(tfhe.GLWEPlaintext[T]{Value: kg.BaseEncryptor.SecretKey.GLWEKey.Value[i]}, kg.Parameters.schemeSwitchParameters)
	}

	return CircuitBootstrapKey[T]{
		SchemeSwitchKey: schemeSwitchKey,
		TraceKeys:       kg.GenGaloisKeysForLWEToGLWECiphertext(kg.Parameters.traceKeySwitchParameters),
	}
}
