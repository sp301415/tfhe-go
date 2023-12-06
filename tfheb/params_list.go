package tfheb

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBoolean is a default parameter set for boolean TFHE.
	ParamsBoolean = tfhe.ParametersLiteral[uint32]{
		LWEDimension:  720,
		GLWEDimension: 2,
		PolyDegree:    512,

		LWEStdDev:  0.000013071021089943935,
		GLWEStdDev: 0.00000004990272175010415,

		BlockSize: 5,

		MessageModulus: 1 << 2,

		BootstrapParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 4,
		},

		UseLargeLWEEntities: false,
	}

	// ParamsBooleanLargeLWEEntities is a parameter set for boolean TFHE
	// with large LWE entities by default.
	ParamsBooleanLargeLWEEntities = tfhe.ParametersLiteral[uint32]{
		LWEDimension:  664,
		GLWEDimension: 2,
		PolyDegree:    512,

		LWEStdDev:  0.0000380828292345977,
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

		UseLargeLWEEntities: true,
	}

	// ParamsOriginalBoolean is parameters from the original C++ TFHE library.
	ParamsOriginalBoolean = tfhe.ParametersLiteral[uint32]{
		LWEDimension:  628,
		GLWEDimension: 1,
		PolyDegree:    1024,

		LWEStdDev:  0.000030517578125,
		GLWEStdDev: 0.0000000298023223876953125,

		BlockSize: 4,

		MessageModulus: 1 << 2,

		BootstrapParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 7,
			Level: 3,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint32]{
			Base:  1 << 2,
			Level: 8,
		},
	}
)
