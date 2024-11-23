package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBinaryParty2 is a parameter set for binary TFHE with 2 parties.
	ParamsBinaryParty2 = ParametersLiteral[uint64]{
		PartyCount: 2,

		SingleLWEDimension: 560,
		PolyDegree:         2048,

		LWEStdDev:  0.0000305,
		GLWEStdDev: 0.00000000000000000463,

		BlockSize: 2,

		MessageModulus: 1 << 1,

		BlindRotateParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 12,
			Level: 3,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 8,
		},
		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 2,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 10,
			Level: 3,
		},
		BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryParty4 is a parameter set for binary TFHE with 4 parties.
	ParamsBinaryParty4 = ParametersLiteral[uint64]{
		PartyCount: 4,

		SingleLWEDimension: 560,
		PolyDegree:         2048,

		LWEStdDev:  0.0000305,
		GLWEStdDev: 0.00000000000000000463,

		BlockSize: 2,

		MessageModulus: 1 << 1,

		BlindRotateParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 5,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 8,
		},
		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 2,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 7,
		},

		BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryParty8 is a parameter set for binary TFHE with 8 parties.
	ParamsBinaryParty8 = ParametersLiteral[uint64]{
		PartyCount: 8,

		SingleLWEDimension: 560,
		PolyDegree:         2048,

		LWEStdDev:  0.0000305,
		GLWEStdDev: 0.00000000000000000463,

		BlockSize: 2,

		MessageModulus: 1 << 1,

		BlindRotateParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 9,
			Level: 4,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 8,
		},
		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 8,
		},

		BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryParty16 is a parameter set for binary TFHE with 16 parties.
	ParamsBinaryParty16 = ParametersLiteral[uint64]{
		PartyCount: 16,

		SingleLWEDimension: 560,
		PolyDegree:         2048,

		LWEStdDev:  0.0000305,
		GLWEStdDev: 0.00000000000000000463,

		BlockSize: 2,

		MessageModulus: 1 << 1,

		BlindRotateParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 5,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 8,
		},

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 9,
		},
		BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryParty32 is a parameter set for binary TFHE with 32 parties.
	ParamsBinaryParty32 = ParametersLiteral[uint64]{
		PartyCount: 32,

		SingleLWEDimension: 560,
		PolyDegree:         2048,

		LWEStdDev:  0.0000305,
		GLWEStdDev: 0.00000000000000000463,

		BlockSize: 2,

		MessageModulus: 1 << 1,

		BlindRotateParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 6,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 8,
		},
		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 16,
		},

		BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
	}
)
