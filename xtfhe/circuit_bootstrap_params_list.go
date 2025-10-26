package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsCircuitBootstrapMedium is a default circuit bootstrapping parameter set for binary TFHE
	// with max depth 1194.
	ParamsCircuitBootstrapMedium = CircuitBootstrapParametersLiteral[uint64]{
		ManyLUTParams: ManyLUTParametersLiteral[uint64]{
			BaseParams: tfhe.ParametersLiteral[uint64]{
				LWEDimension: 571,
				GLWERank:     1,
				PolyRank:     2048,

				LWEStdDev:  0.00016996595057126976,
				GLWEStdDev: 0.0000000000000003472576015484159,

				MessageModulus: 1 << 1,

				BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
					Base:  1 << 15,
					Level: 2,
				},
				KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
					Base:  1 << 2,
					Level: 5,
				},

				BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
			},

			LUTCount: 4,
		},

		SchemeSwitchParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 17,
			Level: 2,
		},
		TraceKeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 13,
			Level: 3,
		},
		OutputParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 4,
		},
	}

	// ParamsCircuitBootstrapLarge is a default circuit bootstrapping parameter set for binary TFHE
	// with max depth 13410.
	ParamsCircuitBootstrapLarge = CircuitBootstrapParametersLiteral[uint64]{
		ManyLUTParams: ManyLUTParametersLiteral[uint64]{
			BaseParams: tfhe.ParametersLiteral[uint64]{
				LWEDimension: 571,
				GLWERank:     1,
				PolyRank:     2048,

				LWEStdDev:  0.00016996595057126976,
				GLWEStdDev: 0.0000000000000003472576015484159,

				MessageModulus: 1 << 1,

				BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
					Base:  1 << 15,
					Level: 2,
				},
				KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
					Base:  1 << 2,
					Level: 5,
				},

				BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
			},

			LUTCount: 4,
		},

		SchemeSwitchParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 17,
			Level: 2,
		},
		TraceKeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 6,
		},
		OutputParams: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 4,
		},
	}
)
