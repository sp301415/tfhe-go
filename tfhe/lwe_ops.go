package tfhe

import (
	"github.com/sp301415/tfhe/math/vec"
)

// AddLWE adds two LWE cipheretexts ct0, ct1 and returns the result.
func (e Evaluater[T]) AddLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.AddLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// AddLWEInPlace adds two LWE ciphertexts ct0, ct1 and writes to ctOut.
func (e Evaluater[T]) AddLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.AddInPlace(ct0.Value, ct1.Value, ctOut.Value)
}

// AddLWEAssign adds LWE ciphertext ct0 to ctOut.
func (e Evaluater[T]) AddLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.AddAssign(ct0.Value, ctOut.Value)
}

// SubLWE subtracts ct0, ct1 and returns the result.
func (e Evaluater[T]) SubLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.SubLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// SubLWEInPlace subtracts ct0, ct1 and writes it to ctOut.
func (e Evaluater[T]) SubLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	vec.SubInPlace(ct0.Value, ct1.Value, ctOut.Value)
}

// SubLWEAssign subtracts ct0 from ctOut.
func (e Evaluater[T]) SubLWEAssign(ct0, ctOut LWECiphertext[T]) {
	vec.SubAssign(ct0.Value, ctOut.Value)
}

// NegLWE negates ct0 and returns the result.
func (e Evaluater[T]) NegLWE(ct0 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.NegLWEInPlace(ct0, ctOut)
	return ctOut
}

// NegLWEInPlace negates ct0 and writes it to ctOut.
func (e Evaluater[T]) NegLWEInPlace(ct0, ctOut LWECiphertext[T]) {
	vec.NegInPlace(ct0.Value, ctOut.Value)
}

// NegLWEAssign negates ct0.
func (e Evaluater[T]) NegLWEAssign(ct0 LWECiphertext[T]) {
	vec.NegAssign(ct0.Value)
}

// ScalarMulLWE multplies c to ct0 and returns the result.
func (e Evaluater[T]) ScalarMulLWE(ct0 LWECiphertext[T], c T) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.ScalarMulLWEInPlace(ct0, c, ctOut)
	return ctOut
}

// ScalarMulLWEInPlace multplies c to ct0 and writes it to ctOut.
func (e Evaluater[T]) ScalarMulLWEInPlace(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulInPlace(ct0.Value, c, ctOut.Value)
}

// ScalarMulLWEAssign multplies c to ctOut.
func (e Evaluater[T]) ScalarMulLWEAssign(c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAssign(c, ctOut.Value)
}

// ScalarMulAddLWEAssign multiplies c to ct1 and adds to ctOut.
func (e Evaluater[T]) ScalarMulAddLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulAddAssign(ct0.Value, c, ctOut.Value)
}

// ScalarMulSubLWEAssign multiplies c to ct0 and subtracts from ctOut.
func (e Evaluater[T]) ScalarMulSubLWEAssign(ct0 LWECiphertext[T], c T, ctOut LWECiphertext[T]) {
	vec.ScalarMulSubAssign(ct0.Value, c, ctOut.Value)
}

// MulLWE multiplies ct0, ct1 and returns the result.
//
// LWE multiplication is notoriously difficult.
// In TFHE-go, currently two approaches are implemented:
//  1. PBS Approach: compute (x+y)^2/4 - (x-y)^2/4 using PBS x -> x^2/4
//  2. Carry Approach: compute (carry, modulus) -> carry * modulus after concat.
//
// If CarryModulus >= MessageModulus, MulLWE chooses second. Otherwise, it chooses first.
// You can call either approch explicitly by MulLWEPBS or MulLWECarry.
func (e Evaluater[T]) MulLWE(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.MulLWEInPlace(ct0, ct1, ctOut)
	return ctOut
}

// MulLWEInPlace multiplies ct0, ct1 and writes it to ctOut.
//
// LWE multiplication is notoriously difficult.
// In TFHE-go, currently two approaches are implemented:
//  1. PBS Approach: compute (x+y)^2/4 - (x-y)^2/4 using PBS x -> x^2/4
//  2. Carry Approach: compute (carry, modulus) -> carry * modulus after concat.
//
// If CarryModulus >= MessageModulus, MulLWE chooses second. Otherwise, it chooses first.
// You can call either approch explicitly by MulLWEPBS or MulLWECarry.
func (e Evaluater[T]) MulLWEInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	if e.Parameters.carryModulus >= e.Parameters.messageModulus {
		e.MulLWECarryInPlace(ct0, ct1, ctOut)
		return
	}
	e.MulLWEPBSInPlace(ct0, ct1, ctOut)
}

// MulLWEAssign multiplies ct0 to ct1.
//
// LWE multiplication is notoriously difficult.
// In TFHE-go, currently two approaches are implemented:
//  1. PBS Approach: compute (x+y)^2/4 - (x-y)^2/4 using PBS x -> x^2/4
//  2. Carry Approach: compute (carry, modulus) -> carry * modulus after concat.
//
// If CarryModulus >= MessageModulus, MulLWE chooses second. Otherwise, it chooses first.
// You can call either approch explicitly by MulLWEPBS or MulLWECarry.
func (e Evaluater[T]) MulLWEAssign(ct0, ct1 LWECiphertext[T]) {
	e.MulLWEInPlace(ct0, ct1, ct1)
}

// MulLWEPBS multiplies ct0, ct1 and returns it using PBS Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWEPBS(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.MulLWEPBSInPlace(ct0, ct1, ctOut)
	return ctOut
}

// MulLWEPBSInPlace multiplies ct0, ct1 and writes it to ctOut using PBS Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWEPBSInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	e.AddLWEInPlace(ct0, ct1, e.buffer.addLWECtForMul)
	e.SubLWEInPlace(ct0, ct1, e.buffer.subLWECtForMul)

	f := func(x int) int {
		mod := int(e.Parameters.messageModulus)
		x %= mod
		if x > mod/2 {
			x = mod - x
		}
		return x * x / 4
	}
	e.GenLookUpTableInPlace(f, e.buffer.emptyLUT)

	e.BootstrapLUTAssign(e.buffer.addLWECtForMul, e.buffer.emptyLUT)
	e.BootstrapLUTAssign(e.buffer.subLWECtForMul, e.buffer.emptyLUT)

	e.SubLWEInPlace(e.buffer.addLWECtForMul, e.buffer.subLWECtForMul, ctOut)
}

// MulLWEPBSAssign multiplies ct0 to ct1 using PBS Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWEPBSAssign(ct0, ct1 LWECiphertext[T]) {
	e.MulLWEPBSInPlace(ct0, ct1, ct1)
}
