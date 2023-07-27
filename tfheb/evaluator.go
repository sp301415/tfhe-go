package tfheb

import (
	"github.com/sp301415/tfhe/tfhe"
)

// Evaluator evaluates homomorphic binary gates on ciphertexts.
// All LWE ciphertexts should be encrypted with tfheb.Encryptor.
//
// This is meant to be public, usually for servers.
type Evaluator struct {
	Parameters    tfhe.Parameters[uint32]
	BaseEvaluator tfhe.Evaluator[uint32]
	signLUT       tfhe.LookUpTable[uint32]
}

// NewEvaluator creates a new Evaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluator(params tfhe.Parameters[uint32], evkey tfhe.EvaluationKey[uint32]) Evaluator {
	signLUT := tfhe.NewLookUpTable[uint32](params)
	for i := 0; i < params.PolyDegree(); i++ {
		signLUT.Value[0].Coeffs[i] = 1 << (32 - 3)
	}
	return Evaluator{
		Parameters:    params,
		BaseEvaluator: tfhe.NewEvaluator(params, evkey),
		signLUT:       signLUT,
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e Evaluator) ShallowCopy() Evaluator {
	return Evaluator{
		Parameters:    e.Parameters,
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		signLUT:       e.signLUT,
	}
}

// NOT computes NOT ct0 and returns the result.
// Equivalent to ^ct0.
func (e Evaluator) NOT(ct0 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NOTInPlace(ct0, ctOut)
	return ctOut
}

// NOTInPlace computes NOT ct0 and writes it to ctOut.
// Equivalent to ^ct0.
func (e Evaluator) NOTInPlace(ct0, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = -ct0
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i]
	}
}

// AND computes ct0 AND ct1 and returns the result.
// Equivalent to ct0 && ct1.
func (e Evaluator) AND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ANDInPlace computes ct0 AND ct1 and writes it to ctOut.
// Equivalent to ct0 && ct1.
func (e Evaluator) ANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// NAND computes ct0 NAND ct1 and returns the result.
// Equivalent to !(ct0 && ct1).
func (e Evaluator) NAND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NANDInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NANDInPlace computes ct0 NAND ct1 and writes it to ctOut.
// Equivalent to !(ct0 && ct1).
func (e Evaluator) NANDInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// OR computes ct0 OR ct1 and returns the result.
// Equivalent to ct0 || ct1.
func (e Evaluator) OR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// ORInPlace computes ct0 OR ct1 and writes it to ctOut.
// Equivalent to ct0 || ct1.
func (e Evaluator) ORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// NOR computes ct0 NOR ct1 and returns the result.
// Equivalent to !(ct0 || ct1).
func (e Evaluator) NOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// NORInPlace computes ct0 NOR ct1 and writes it to ctOut.
// Equivalent to !(ct0 || ct1).
func (e Evaluator) NORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// XOR computes ct0 XOR ct1 and returns the result.
// Equivalent to ct0 != ct1.
func (e Evaluator) XOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// XORInPlace computes ct0 XOR ct1 and writes it to ctOut.
// Equivalent to ct0 != ct1.
func (e Evaluator) XORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = 2*(ct0 + ct1) + 1/4
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (32 - 2)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}

// XNOR computes ct0 XNOR ct1 and returns the result.
// Equivalent to ct0 == ct1.
func (e Evaluator) XNOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XNORInPlace(ct0, ct1, ctOut)
	return ctOut
}

// XNORInPlace computes ct0 XNOR ct1 and writes it to ctOut.
// Equivalent to ct0 == ct1.
func (e Evaluator) XNORInPlace(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = -2*(ct0 + ct1) - 1/4
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (32 - 2)

	e.BaseEvaluator.BootstrapLUTInPlace(ctOut, e.signLUT, ctOut)
}
