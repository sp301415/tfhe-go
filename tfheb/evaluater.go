package tfheb

import (
	"github.com/sp301415/tfhe/tfhe"
)

// Evaluater evaluates homomorphic binary gates on ciphertexts.
// All LWE ciphertexts should be encrypted with tfheb.Encrypter.
//
// This is meant to be public, usually for servers.
type Evaluater struct {
	tfhe.Evaluater[uint32]
	signLUT tfhe.LookUpTable[uint32]
}

// NewEvaluater creates a new Evaluater based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluater(params tfhe.Parameters[uint32], evkey tfhe.EvaluationKey[uint32]) Evaluater {
	signLUT := tfhe.NewLookUpTable[uint32](params)
	for i := 0; i < params.PolyDegree(); i++ {
		signLUT.Value[0].Coeffs[i] = 1 << (32 - 3)
	}
	return Evaluater{
		Evaluater: tfhe.NewEvaluater(params, evkey),
		signLUT:   signLUT,
	}
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
	// ctOut = -ct0
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i]
	}
}

// AND computes ct0 AND ct1 and returns the result.
func (e Evaluater) AND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ANDInPlace computes ct0 AND ct1 and writes it to ctOut.
func (e Evaluater) ANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// NAND computes ct0 NAND ct1 and returns the result.
func (e Evaluater) NAND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NANDInPlace computes ct0 NAND ct1 and writes it to ctOut.
func (e Evaluater) NANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// OR computes ct0 OR ct1 and returns the result.
func (e Evaluater) OR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ORInPlace computes ct0 OR ct1 and writes it to ctOut.
func (e Evaluater) ORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// NOR computes ct0 AND ct1 and returns the result.
func (e Evaluater) NOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NORInPlace computes ct0 OR ct1 and writes it to ctOut.
func (e Evaluater) NORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// XOR computes ct0 AND ct1 and returns the result.
func (e Evaluater) XOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// XORInPlace computes ct0 XOR ct1 and writes it to ctOut.
func (e Evaluater) XORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = 2*(ct0 + ct1) + 1/4
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (32 - 2)

	e.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}
