package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBFVKeySwitchLogN11 is a gadget parameter set for keyswitching keys in BFV type operations
	// where N = 2^11 = 2048.
	ParamsBFVKeySwitchLogN11 = tfhe.GadgetParametersLiteral[uint64]{
		Base:  1 << 9,
		Level: 4,
	}
)
