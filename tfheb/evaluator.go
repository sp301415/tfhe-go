package tfheb

import (
	"github.com/sp301415/tfhe/math/vec"
	"github.com/sp301415/tfhe/tfhe"
)

// Evaluator evaluates homomorphic binary gates on ciphertexts.
// All LWE ciphertexts should be encrypted with tfheb.Encryptor.
// This is meant to be public, usually for servers.
type Evaluator struct {
	*Encoder
	Parameters    tfhe.Parameters[uint32]
	BaseEvaluator *tfhe.Evaluator[uint32]
	signLUT       tfhe.LookUpTable[uint32]
}

// NewEvaluator creates a new Evaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewEvaluator(params tfhe.Parameters[uint32], evkey tfhe.EvaluationKey[uint32]) *Evaluator {
	signLUT := tfhe.NewLookUpTable[uint32](params)
	vec.Fill(signLUT.Coeffs, 1<<(32-3))

	return &Evaluator{
		Encoder:       NewEncoder(params),
		Parameters:    params,
		BaseEvaluator: tfhe.NewEvaluator(params, evkey),
		signLUT:       signLUT,
	}
}

// ShallowCopy returns a shallow copy of this Evaluator.
// Returned Evaluator is safe for concurrent use.
func (e *Evaluator) ShallowCopy() *Evaluator {
	return &Evaluator{
		Encoder:       e.Encoder,
		Parameters:    e.Parameters,
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		signLUT:       e.signLUT,
	}
}

// NOT computes NOT ct0 and returns the result.
// Equivalent to ^ct0.
func (e *Evaluator) NOT(ct0 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NOTAssign(ct0, ctOut)
	return ctOut
}

// NOTAssign computes NOT ct0 and writes it to ctOut.
// Equivalent to ^ct0.
func (e *Evaluator) NOTAssign(ct0, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = -ct0
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i]
	}
}

// AND computes ct0 AND ct1 and returns the result.
// Equivalent to ct0 && ct1.
func (e *Evaluator) AND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// ANDAssign computes ct0 AND ct1 and writes it to ctOut.
// Equivalent to ct0 && ct1.
func (e *Evaluator) ANDAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NAND computes ct0 NAND ct1 and returns the result.
// Equivalent to !(ct0 && ct1).
func (e *Evaluator) NAND(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// NANDAssign computes ct0 NAND ct1 and writes it to ctOut.
// Equivalent to !(ct0 && ct1).
func (e *Evaluator) NANDAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// OR computes ct0 OR ct1 and returns the result.
// Equivalent to ct0 || ct1.
func (e *Evaluator) OR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.ORAssign(ct0, ct1, ctOut)
	return ctOut
}

// ORAssign computes ct0 OR ct1 and writes it to ctOut.
// Equivalent to ct0 || ct1.
func (e *Evaluator) ORAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = ct0 + ct1 + 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NOR computes ct0 NOR ct1 and returns the result.
// Equivalent to !(ct0 || ct1).
func (e *Evaluator) NOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.NORAssign(ct0, ct1, ctOut)
	return ctOut
}

// NORAssign computes ct0 NOR ct1 and writes it to ctOut.
// Equivalent to !(ct0 || ct1).
func (e *Evaluator) NORAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = - ct0 - ct1 - 1/8
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= 1 << (32 - 3)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XOR computes ct0 XOR ct1 and returns the result.
// Equivalent to ct0 != ct1.
func (e *Evaluator) XOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XORAssign computes ct0 XOR ct1 and writes it to ctOut.
// Equivalent to ct0 != ct1.
func (e *Evaluator) XORAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = 2*(ct0 + ct1) + 1/4
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (ct0.Value[i] + ct1.Value[i])
	}
	ctOut.Value[0] += 1 << (32 - 2)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XNOR computes ct0 XNOR ct1 and returns the result.
// Equivalent to ct0 == ct1.
func (e *Evaluator) XNOR(ct0, ct1 tfhe.LWECiphertext[uint32]) tfhe.LWECiphertext[uint32] {
	ctOut := tfhe.NewLWECiphertext(e.Parameters)
	e.XNORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XNORAssign computes ct0 XNOR ct1 and writes it to ctOut.
// Equivalent to ct0 == ct1.
func (e *Evaluator) XNORAssign(ct0, ct1, ctOut tfhe.LWECiphertext[uint32]) {
	// ctOut = -2*(ct0 + ct1) - 1/4
	for i := 0; i < e.Parameters.LWEDimension()+1; i++ {
		ctOut.Value[i] = 2 * (-ct0.Value[i] - ct1.Value[i])
	}
	ctOut.Value[0] -= 1 << (32 - 2)

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}
