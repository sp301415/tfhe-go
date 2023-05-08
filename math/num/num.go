// Package num implements various utility functions regarding constraints.Integer.
package num

import (
	"math"
	"math/bits"

	"golang.org/x/exp/constraints"
)

// Abs returns the absolute value of x.
func Abs[T constraints.Integer](x T) T {
	if x < 0 {
		return -x
	}
	return x
}

// MaxT returns the maximum possible value of type T in uint64.
func MaxT[T constraints.Integer]() uint64 {
	var z T
	switch any(z).(type) {
	case int:
		return math.MaxInt
	case uint:
		return math.MaxUint
	case int8:
		return math.MaxInt8
	case uint8:
		return math.MaxUint8
	case int16:
		return math.MaxInt16
	case uint16:
		return math.MaxUint16
	case int32:
		return math.MaxInt32
	case uint32:
		return math.MaxUint32
	case int64:
		return math.MaxInt64
	case uint64:
		return math.MaxUint64
	case uintptr:
		return math.MaxUint
	}
	return math.MaxUint
}

// SizeT returns the bits required to express value of type T in int.
func SizeT[T constraints.Integer]() int {
	var z T
	switch any(z).(type) {
	case int, uint, uintptr:
		return bits.UintSize
	case int8, uint8:
		return 8
	case int16, uint16:
		return 16
	case int32, uint32:
		return 32
	case int64, uint64:
		return 64
	}
	return 64
}

// MinT returns the minimum possible value of type T in int64.
func MinT[T constraints.Integer]() int64 {
	var z T
	switch any(z).(type) {
	case int:
		return math.MinInt
	case int8:
		return math.MinInt8
	case int16:
		return math.MinInt16
	case int32:
		return math.MinInt32
	case int64:
		return math.MinInt64
	}
	return 0
}

// IsSigned returns if type T is a signed integer type.
func IsSigned[T constraints.Integer]() bool {
	var z T
	return z-1 < 0
}

// FromFloat64 casts a float64 value to T, wrapping around.
// If float64 is not valid (NaN, Inf), it returns 0.
func FromFloat64[T constraints.Integer](f float64) T {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}

	return T(math.Round(f))
}

// IsPowerOfTwo returns whether x is a power of two.
// If x <= 0, it always returns false.
func IsPowerOfTwo[T constraints.Integer](x T) bool {
	return (x > 0) && (x&(x-1)) == 0
}

// Log2 returns floor(log2(x)).
// If x == 0, it returns 0.
func Log2[T constraints.Integer](x T) int {
	if x == 0 {
		return 0
	}
	return int(bits.Len64(uint64(x))) - 1
}

// RoundRatio returns round(x/y).
func RoundRatio[T constraints.Integer](x, y T) T {
	ratio := x / y
	if 2*(x%y) >= y {
		ratio += 1
	}
	return ratio
}

// RoundRatioBits is a bit-optimzed version of RoundRatio: it computes round(x/2^bits).
//   - If bits == 0, then it returns x.
//   - If bits < 0, it panics.
func RoundRatioBits[T constraints.Integer](x T, bits int) T {
	if bits == 0 {
		return x
	}

	// Compute the ratio
	ratio := x >> bits
	// Compute the first decimal: if it is 1, then we should round up
	decimal := (x >> (bits - 1)) & 1
	ratio += decimal // Equivalant to if decimal == 1 { ratio += 1 }
	return ratio
}

// ClosestMultiple returns the closest multiple of x respect to y
// It is same as round(x/y) * y.
func ClosestMultiple[T constraints.Integer](x, y T) T {
	return RoundRatio(x, y) * y
}

// ClosestMultipleBits returns the closest multiple of x respect to 2^bits.
// It is same as round(x/2^bits) * 2^bits.
func ClosestMultipleBits[T constraints.Integer](x T, bits int) T {
	return RoundRatioBits(x, bits) << bits
}

// Gcd returns the GCD(Greatest Common Divisor) of x and y.
//   - If x = y = 0, Gcd returns 0.
//   - If x = 0 and y != 0, Gcd returns |y|.
//   - If x != 0 and y = 0, Gcd returns |x|.
func Gcd[T constraints.Integer](x, y T) T {
	switch {
	case x == 0 && y == 0:
		return 0
	case x == 0 && y != 0:
		return Abs(y)
	case x != 0 && y == 0:
		return Abs(x)
	}

	x, y = Abs(x), Abs(y)
	for y > 0 {
		x, y = y, x%y
	}
	return x
}

// Min returns the smaller value between x and y.
func Min[T constraints.Integer](x, y T) T {
	if x < y {
		return x
	}
	return y
}

// Max returns the larger value between x and y.
func Max[T constraints.Integer](x, y T) T {
	if x > y {
		return x
	}
	return y
}
