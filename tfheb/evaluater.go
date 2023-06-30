package tfheb

import (
	"github.com/sp301415/tfhe/tfhe"
)

// Evaluater evaluates homomorphic binary gates on ciphertexts.
// Therefore, it assumes every ciphertext encrypts 0 or 1.
//
// This is meant to be public, usually for servers.
type Evaluater struct {
	tfhe.Evaluater[uint32]
}

// NewEvaluater creates a new Evaluater based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluater(params tfhe.Parameters[uint32], evkey tfhe.EvaluationKey[uint32]) Evaluater {
	return Evaluater{Evaluater: tfhe.NewEvaluater(params, evkey)}
}

// ShallowCopy returns a shallow copy of this Evaluater.
// Returned Evaluater is safe for concurrent use.
func (e Evaluater) ShallowCopy() Evaluater {
	return Evaluater{Evaluater: e.Evaluater.ShallowCopy()}
}

// NOT computes NOT ct0 and returns the result.
func (e Evaluater) NOT(ct0 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NOTInPlace(ct0, ctOut)
	return ctOut
}

// NOTInPlace computes NOT ct0 and writes it to ctOut.
func (e Evaluater) NOTInPlace(ct0, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0:
			return 1
		case 1:
			return 0
		}
		return 0
	}

	e.BootstrapFuncInPlace(ct0, f, ctOut)
}

// AND computes ct0 AND ct1 and returns the result.
func (e Evaluater) AND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ANDInPlace computes ct0 AND ct1 and writes it to ctOut.
func (e Evaluater) ANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0, 1:
			return 0
		case 2:
			return 1
		}
		return 0
	}

	e.AddLWEInPlace(ct0, ct1, ctOut)
	e.BootstrapFuncAssign(f, ctOut)
}

// NAND computes ct0 NAND ct1 and returns the result.
func (e Evaluater) NAND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NANDInPlace computes ct0 NAND ct1 and writes it to ctOut.
func (e Evaluater) NANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0, 1:
			return 1
		case 2:
			return 0
		}
		return 0
	}

	e.AddLWEInPlace(ct0, ct1, ctOut)
	e.BootstrapFuncAssign(f, ctOut)
}

// OR computes ct0 OR ct1 and returns the result.
func (e Evaluater) OR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ORInPlace computes ct0 OR ct1 and writes it to ctOut.
func (e Evaluater) ORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0:
			return 0
		case 1, 2:
			return 1
		}
		return 0
	}

	e.AddLWEInPlace(ct0, ct1, ctOut)
	e.BootstrapFuncAssign(f, ctOut)
}

// NOR computes ct0 AND ct1 and returns the result.
func (e Evaluater) NOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NORInPlace computes ct0 OR ct1 and writes it to ctOut.
func (e Evaluater) NORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0:
			return 1
		case 1, 2:
			return 0
		}
		return 0
	}

	e.AddLWEInPlace(ct0, ct1, ctOut)
	e.BootstrapFuncAssign(f, ctOut)
}

// XOR computes ct0 AND ct1 and returns the result.
func (e Evaluater) XOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// XORInPlace computes ct0 XOR ct1 and writes it to ctOut.
func (e Evaluater) XORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	f := func(x int) int {
		switch x {
		case 0, 2:
			return 0
		case 1:
			return 1
		}
		return 0
	}

	e.AddLWEInPlace(ct0, ct1, ctOut)
	e.BootstrapFuncAssign(f, ctOut)
}
