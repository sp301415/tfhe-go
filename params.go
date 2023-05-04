package tfhe

// Tint represents the integer in the discretized torus.
// Currently, it supports Q = 2^32 and Q = 2^64 (uint32 and uint64).
type Tint interface {
	uint32 | uint64
}

// Parameters is a structure for binary TFHE parameters.
//
// Unless you are a cryptographic expert, DO NOT set these by yourself;
// always use the default parameters provided.
type Parameters[T Tint] struct {
	// LWEDimension is the dimension of LWE lattice used. Usually this is denoted by n.
	// Length of LWE secret key is LWEDimension, and the length of LWE ciphertext is LWEDimension+1.
	LWEDimension int
	// GLWEDimension is the dimension of GLWE lattice used. Usually this is denoted by k.
	// Length of GLWE secret key is GLWEDimension, and the length of GLWE ciphertext is GLWEDimension+1.
	GLWEDimension int
	// PolyDegree is the degree of polynomials in GLWE entities. Usually this is denoted by N.
	PolyDegree int

	// LWEStdDev is the standard deviation used for gaussian error sampling in LWE encryption.
	LWEStdDev float64
	// GLWEStdDev is the standard deviation used for gaussian error sampling in GLWE encryption.
	GLWEStdDev float64

	// Delta is the scaling factor used for message encoding.
	// The lower log(Delta) bits are reserved for errors.
	Delta int

	PBSBaseLog int
	PBSLevel   int

	KeySwitchBaseLog int
	KeySwitchLevel   int
}

var (
	// BooleanParameters is a default boolean parameters set with 128-bit security.
	BooleanParameters = Parameters[uint32]{
		LWEDimension:  777,
		GLWEDimension: 3,
		PolyDegree:    512,

		LWEStdDev:  0.000003725679281679651,
		GLWEStdDev: 0.0000000000034525330484572114,

		Delta: 1 << 24,
	}
)
