package tfheb

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBoolean is a default parameter set for boolean TFHE.
	ParamsBoolean = tfhe.ParametersLiteral[uint32]{
		LWESmallDimension: 664,
		GLWEDimension:     2,
		PolyDegree:        512,

		LWEStdDev:  0.00003808282923459771,
		GLWEStdDev: 0.00000004990272175010415,

		BlockSize: 4,

		MessageModulus: 1 << 2,

		BootstrapParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 4,
		},
	}
)
