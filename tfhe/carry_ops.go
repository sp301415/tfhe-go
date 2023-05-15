package tfhe

// ConcatInPlace concats ct0, ct1 and writes it to ctOut.
//
// Panics if CarryModulus < MessageModulus.
func (e Evaluater[T]) ConcatInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	if e.Parameters.carryModulus < e.Parameters.messageModulus {
		panic("not enough carry space")
	}
	e.ScalarMulLWEInPlace(ct0, e.Parameters.messageModulus, ctOut)
	e.AddLWEAssign(ct1, ctOut)
}

// carryAndMessage splits encoded message to carry and message.
func carryAndMessage(m, mod int) (int, int) {
	return (m >> mod) % mod, m % mod
}

// Equals compares ct0, ct1 and returns the result.
func (e Evaluater[T]) Equals(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.EqualsInPlace(ct0, ct1, ctOut)
	return ctOut
}

// EqualsInPlace compares ct0, ct1 and writes it to ctOut.
func (e Evaluater[T]) EqualsInPlace(ct0, ct1 LWECiphertext[T], ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		if m0 == m1 {
			return 0
		}
		return 1
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// GreaterThan computes ct0 > ct1 and returns it.
func (e Evaluater[T]) GreaterThan(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.GreaterThanInPlace(ct0, ct1, ctOut)
	return ctOut
}

// GreaterThanInPlace computes ct0 > ct1 and writes it to ctOut.
func (e Evaluater[T]) GreaterThanInPlace(ct0, ct1 LWECiphertext[T], ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		if m0 > m1 {
			return 0
		}
		return 1
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// GreaterOrEqualThan computes ct0 >= ct1 and returns it.
func (e Evaluater[T]) GreaterOrEqualThan(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.GreaterOrEqualThanInPlace(ct0, ct1, ctOut)
	return ctOut
}

// GreaterOrEqualThanInPlace computes ct0 >= ct1 and writes it to ctOut.
func (e Evaluater[T]) GreaterOrEqualThanInPlace(ct0, ct1 LWECiphertext[T], ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		if m0 >= m1 {
			return 0
		}
		return 1
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// LessThan computes ct0 < ct1 and returns it.
func (e Evaluater[T]) LessThan(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.LessThanInPlace(ct0, ct1, ctOut)
	return ctOut
}

// LesshanInPlace computes ct0 > ct1 and writes it to ctOut.
func (e Evaluater[T]) LessThanInPlace(ct0, ct1 LWECiphertext[T], ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		if m0 < m1 {
			return 0
		}
		return 1
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// LessOrEqualThan computes ct0 >= ct1 and returns it.
func (e Evaluater[T]) LessOrEqualThan(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.LessOrEqualThanInPlace(ct0, ct1, ctOut)
	return ctOut
}

// LessOrEqualThanInPlace computes ct0 >= ct1 and writes it to ctOut.
func (e Evaluater[T]) LessOrEqualThanInPlace(ct0, ct1 LWECiphertext[T], ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		if m0 >= m1 {
			return 0
		}
		return 1
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// MulLWECarry multiplies ct0, ct1 and retuns the result using Carry Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWECarry(ct0, ct1 LWECiphertext[T]) LWECiphertext[T] {
	ctOut := NewLWECiphertext(e.Parameters)
	e.MulLWECarryInPlace(ct0, ct1, ctOut)
	return ctOut
}

// MulLWECarryInPlace multiplies ct0, ct1 writes the result to ctOut using Carry Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWECarryInPlace(ct0, ct1, ctOut LWECiphertext[T]) {
	f := func(x int) int {
		m0, m1 := carryAndMessage(x, int(e.Parameters.messageModulus))
		return (m0 * m1) % int(e.Parameters.messageModulus)
	}
	e.ConcatInPlace(ct0, ct1, e.buffer.twoLWECtForOps)
	e.BootstrapFuncInPlace(e.buffer.twoLWECtForOps, f, ctOut)
}

// MulLWECarryAssign multiplies ct0 to ct1 using Carry Approach.
// See MulLWE for more details.
func (e Evaluater[T]) MulLWECarryAssign(ct0, ct1 LWECiphertext[T]) {
	e.MulLWECarryInPlace(ct0, ct1, ct1)
}
