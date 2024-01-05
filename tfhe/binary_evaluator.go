package tfhe

import (
	"github.com/sp301415/tfhe-go/math/vec"
)

// BinaryEvaluator evaluates homomorphic binary gates on ciphertexts.
// All LWE ciphertexts should be encrypted with tfhe.BinaryEncryptor.
// This is meant to be public, usually for servers.
type BinaryEvaluator struct {
	*BinaryEncoder
	Parameters    Parameters[uint32]
	BaseEvaluator *Evaluator[uint32]
	signLUT       LookUpTable[uint32]
}

// NewBinaryEvaluator creates a new BinaryEvaluator based on parameters.
// This does not copy evaluation keys, since they are large.
func NewBinaryEvaluator(params Parameters[uint32], evk EvaluationKey[uint32]) *BinaryEvaluator {
	signLUT := NewLookUpTable[uint32](params)
	vec.Fill(signLUT.Coeffs, params.delta)

	return &BinaryEvaluator{
		BinaryEncoder: NewBinaryEncoder(params),
		Parameters:    params,
		BaseEvaluator: NewEvaluator(params, evk),
		signLUT:       signLUT,
	}
}

// ShallowCopy returns a shallow copy of this BinaryEvaluator.
// Returned BinaryEvaluator is safe for concurrent use.
func (e *BinaryEvaluator) ShallowCopy() *BinaryEvaluator {
	return &BinaryEvaluator{
		BinaryEncoder: e.BinaryEncoder,
		Parameters:    e.Parameters,
		BaseEvaluator: e.BaseEvaluator.ShallowCopy(),
		signLUT:       e.signLUT,
	}
}

// NOT computes NOT ct0 and returns the result.
// Equivalent to ^ct0.
func (e *BinaryEvaluator) NOT(ct0 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NOTAssign(ct0, ctOut)
	return ctOut
}

// NOTAssign computes NOT ct0 and writes it to ctOut.
// Equivalent to ^ct0.
func (e *BinaryEvaluator) NOTAssign(ct0, ctOut LWECiphertext[uint32]) {
	// ctOut = -ct0
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = -ct0.Value[i]
	}
}

// AND computes ct0 AND ct1 and returns the result.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator) AND(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// ANDAssign computes ct0 AND ct1 and writes it to ctOut.
// Equivalent to ct0 && ct1.
func (e *BinaryEvaluator) ANDAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] -= e.Parameters.delta

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NAND computes ct0 NAND ct1 and returns the result.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator) NAND(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NANDAssign(ct0, ct1, ctOut)
	return ctOut
}

// NANDAssign computes ct0 NAND ct1 and writes it to ctOut.
// Equivalent to !(ct0 && ct1).
func (e *BinaryEvaluator) NANDAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] += e.Parameters.delta

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// OR computes ct0 OR ct1 and returns the result.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator) OR(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ORAssign(ct0, ct1, ctOut)
	return ctOut
}

// ORAssign computes ct0 OR ct1 and writes it to ctOut.
// Equivalent to ct0 || ct1.
func (e *BinaryEvaluator) ORAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = ct0.Value[i] + ct1.Value[i]
	}
	ctOut.Value[0] += e.Parameters.delta

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// NOR computes ct0 NOR ct1 and returns the result.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator) NOR(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NORAssign(ct0, ct1, ctOut)
	return ctOut
}

// NORAssign computes ct0 NOR ct1 and writes it to ctOut.
// Equivalent to !(ct0 || ct1).
func (e *BinaryEvaluator) NORAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = -ct0.Value[i] - ct1.Value[i]
	}
	ctOut.Value[0] -= e.Parameters.delta

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XOR computes ct0 XOR ct1 and returns the result.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator) XOR(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XORAssign computes ct0 XOR ct1 and writes it to ctOut.
// Equivalent to ct0 != ct1.
func (e *BinaryEvaluator) XORAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = (ct0.Value[i] + ct1.Value[i]) << (e.Parameters.messageModulusLog - 1)
	}
	ctOut.Value[0] += e.Parameters.delta << 1

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}

// XNOR computes ct0 XNOR ct1 and returns the result.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator) XNOR(ct0, ct1 LWECiphertext[uint32]) LWECiphertext[uint32] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.XNORAssign(ct0, ct1, ctOut)
	return ctOut
}

// XNORAssign computes ct0 XNOR ct1 and writes it to ctOut.
// Equivalent to ct0 == ct1.
func (e *BinaryEvaluator) XNORAssign(ct0, ct1, ctOut LWECiphertext[uint32]) {
	for i := 0; i < e.Parameters.lweDimension+1; i++ {
		ctOut.Value[i] = (-ct0.Value[i] - ct1.Value[i]) << (e.Parameters.messageModulusLog - 1)
	}
	ctOut.Value[0] -= e.Parameters.delta

	e.BaseEvaluator.BootstrapLUTAssign(ctOut, e.signLUT, ctOut)
}
