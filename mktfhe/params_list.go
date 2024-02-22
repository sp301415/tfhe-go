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

			LWEStdDev:  3.05e-10 * (1 << 64),
			GLWEStdDev: 4.63e-18 * (1 << 64),

			BlockSize: 1,

			MessageModulus: 1 << 2,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 12,
				Level: 3,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 2,
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
)
