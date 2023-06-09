package tfheb

import "github.com/sp301415/tfhe/tfhe"

var (
	// ParamsBoolean is a default parameter set for boolean TFHE.
	ParamsBoolean = tfhe.ParametersLiteral[uint32]{
		LWEDimension:  777,
		GLWEDimension: 3,
		PolyDegree:    512,

		LWEStdDev:  0.000003725679281679651,
		GLWEStdDev: 0.0000000000034525330484572114,

		BlockSize: 3,

		MessageModulus: 1 << 2,

		BootstrapParameters: tfhe.DecompositionParametersLiteral[uint32]{
			Base:  1 << 18,
			Level: 1,
		},
		KeySwitchParameters: tfhe.DecompositionParametersLiteral[uint32]{
			Base:  1 << 4,
			Level: 3,
		},
	}

	// ParamsOriginalBoolean is parameters from the original C++ TFHE library.
	ParamsOriginalBoolean = tfhe.ParametersLiteral[uint32]{
		LWEDimension:  828,
		GLWEDimension: 2,
		PolyDegree:    1024,

		LWEStdDev:  0.000001412290588219445,
		GLWEStdDev: 0.00000000000000029403601535432533,

		BlockSize: 4,

		MessageModulus: 1 << 2,

		BootstrapParameters: tfhe.DecompositionParametersLiteral[uint32]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: tfhe.DecompositionParametersLiteral[uint32]{
			Base:  1 << 5,
			Level: 3,
		},
	}
)
