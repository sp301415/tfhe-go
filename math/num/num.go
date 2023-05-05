package num

import (
	"math"
	"math/bits"

	"golang.org/x/exp/constraints"
)

// Abs returns the absolute value of x.
func Abs[T constraints.Signed](x T) T {
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

	panic("unreachable")
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

// RoundRatio returns round(a/b).
func RoundRatio[T constraints.Integer](a, b T) T {
	ratio := a / b
	if 2*(a%b) >= b {
		ratio += 1
	}
	return ratio
}
