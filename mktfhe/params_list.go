package mktfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBinaryParty2 is a parameter set for binary TFHE with 2 parties.
	ParamsBinaryParty2 = ParametersLiteral[uint64]{
		ParametersLiteral: tfhe.ParametersLiteral[uint64]{
			LWEDimension:    560,
			GLWEDimension:   1,
			PolyDegree:      2048,
			PolyLargeDegree: 2048,

			LWEStdDev:  0.0000305,
			GLWEStdDev: 0.0000000000000000043,

			BlockSize: 2,

			MessageModulus: 1 << 1,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 12,
				Level: 3,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 1,
				Level: 8,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		PartyCount: 2,

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 2,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 10,
			Level: 3,
		},
	}

	// ParamsBinaryParty4 is a parameter set for binary TFHE with 4 parties.
	ParamsBinaryParty4 = ParametersLiteral[uint64]{
		ParametersLiteral: tfhe.ParametersLiteral[uint64]{
			LWEDimension:    560,
			GLWEDimension:   1,
			PolyDegree:      2048,
			PolyLargeDegree: 2048,

			LWEStdDev:  0.0000305,
			GLWEStdDev: 0.0000000000000000043,

			BlockSize: 2,

			MessageModulus: 1 << 1,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 8,
				Level: 5,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 1,
				Level: 8,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		PartyCount: 4,

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 2,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 7,
		},
	}

	// ParamsBinaryParty8 is a parameter set for binary TFHE with 8 parties.
	ParamsBinaryParty8 = ParametersLiteral[uint64]{
		ParametersLiteral: tfhe.ParametersLiteral[uint64]{
			LWEDimension:    560,
			GLWEDimension:   1,
			PolyDegree:      2048,
			PolyLargeDegree: 2048,

			LWEStdDev:  0.0000305,
			GLWEStdDev: 0.0000000000000000043,

			BlockSize: 2,

			MessageModulus: 1 << 1,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 9,
				Level: 4,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 1,
				Level: 8,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		PartyCount: 8,

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 8,
		},
	}

	// ParamsBinaryParty16 is a parameter set for binary TFHE with 16 parties.
	ParamsBinaryParty16 = ParametersLiteral[uint64]{
		ParametersLiteral: tfhe.ParametersLiteral[uint64]{
			LWEDimension:    560,
			GLWEDimension:   1,
			PolyDegree:      2048,
			PolyLargeDegree: 2048,

			LWEStdDev:  0.0000305,
			GLWEStdDev: 0.0000000000000000043,

			BlockSize: 2,

			MessageModulus: 1 << 1,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 8,
				Level: 5,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 1,
				Level: 8,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		PartyCount: 16,

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 9,
		},
	}

	// ParamsBinaryParty32 is a parameter set for binary TFHE with 32 parties.
	ParamsBinaryParty32 = ParametersLiteral[uint64]{
		ParametersLiteral: tfhe.ParametersLiteral[uint64]{
			LWEDimension:    560,
			GLWEDimension:   1,
			PolyDegree:      2048,
			PolyLargeDegree: 2048,

			LWEStdDev:  0.0000305,
			GLWEStdDev: 0.0000000000000000043,

			BlockSize: 2,

			MessageModulus: 1 << 1,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 7,
				Level: 6,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 1,
				Level: 8,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		PartyCount: 32,

		AccumulatorParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},
		RelinKeyParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 1,
			Level: 16,
		},
	}
)
