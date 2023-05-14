// Package num implements various utility functions regarding constraints.Integer.
package num

import (
	"math"
	"math/bits"
)

// Unsigned represents the unsigned Integer type.
type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Integer represents the Integer type.
type Integer interface {
	Unsigned | ~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Real represents the Integer and Float type.
type Real interface {
	Integer | ~float32 | ~float64
}

// Number represents Integer, Float, and Complex types.
type Number interface {
	Real | ~complex64 | ~complex128
}

// Abs returns the absolute value of x.
func Abs[T Real](x T) T {
	if x < 0 {
		return -x
	}
	return x
}

// MaxT returns the maximum possible value of type T in uint64.
func MaxT[T Integer]() uint64 {
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
func SizeT[T Integer]() int {
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
func MinT[T Integer]() int64 {
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

// IsSigned returns if type T is a signed type.
func IsSigned[T Real]() bool {
	var z T
	return z-1 < 0
}

// FromFloat64 wraps casts a float64 value to T.
func FromFloat64[T Integer](f float64) T {
	return T(math.Round(f))
}

// ToWrappingFloat64 casts a T value to float64.
// If T is unsigned, then it is first cast to signed value.
func ToWrappingFloat64[T Integer](x T) float64 {
	if IsSigned[T]() {
		return float64(x)
	}

	var z T
	switch any(z).(type) {
	case uint, uintptr:
		return float64(int(x))
	case uint8:
		return float64(int8(x))
	case uint16:
		return float64(int16(x))
	case uint32:
		return float64(int32(x))
	case uint64:
		return float64(int64(x))
	}
	return float64(x)
}

// IsPowerOfTwo returns whether x is a power of two.
// If x <= 0, it always returns false.
func IsPowerOfTwo[T Integer](x T) bool {
	return (x > 0) && (x&(x-1)) == 0
}

// Log2 returns floor(log2(x)).
// If x == 0, it returns 0.
func Log2[T Integer](x T) int {
	if x == 0 {
		return 0
	}
	return int(bits.Len64(uint64(x))) - 1
}

// RoundRatioBits is a bit-optimzed version of RoundRatio: it computes round(x/2^bits).
//   - If bits == 0, then it returns x.
//   - If bits < 0, it panics.
func RoundRatioBits[T Integer](x T, bits int) T {
	return ClosestMultipleBits(x, bits) >> bits
}

// ClosestMultipleBits returns the closest multiple of x respect to 2^bits.
// It is same as round(x/2^bits) * 2^bits.
//   - If bits == 0, then it returns x.
//   - If bits < 0, it panics.
func ClosestMultipleBits[T Integer](x T, bits int) T {
	if bits == 0 {
		return x
	}

	carry := x & (1 << (bits - 1))
	return x + carry<<1
}

// Min returns the smaller value between x and y.
func Min[T Real](x, y T) T {
	if x < y {
		return x
	}
	return y
}

// Max returns the larger value between x and y.
func Max[T Real](x, y T) T {
	if x > y {
		return x
	}
	return y
}

// MaxN returns the largest number of x.
// If x is empty, it returns the zero value of T.
func MaxN[T Real](x ...T) T {
	var max T
	if len(x) == 0 {
		return max
	}

	max = x[0]
	for _, v := range x {
		if v > max {
			max = v
		}
	}
	return max
}

// MaxN returns the smallest number of x.
// If x is empty, it returns the zero value of T.
func MinN[T Real](x ...T) T {
	var min T
	if len(x) == 0 {
		return min
	}

	min = x[0]
	for _, v := range x {
		if v < min {
			min = v
		}
	}
	return min
}

// Pow returns x^y. Panics if y < 0.
func Pow[T Integer](x, y T) T {
	// Common cases
	switch {
	case y < 0:
		panic("negative exponent")
	case x == 0:
		return 0
	case y == 0:
		return 1
	case x == 1:
		return 1
	case x == 2:
		return 1 << y
	}

	var r T = 1
	for y > 0 {
		if y&1 == 1 {
			r *= x
		}
		x *= x
		y >>= 1
	}
	return r
}
