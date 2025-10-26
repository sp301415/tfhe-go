package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsFHEWBinary is a default parameter set for binary FHEW.
	ParamsFHEWBinary = FHEWParametersLiteral[uint64]{
		BaseParams: tfhe.ParametersLiteral[uint64]{
			LWEDimension: 447,
			GLWERank:     1,
			PolyRank:     1024,

			LWEStdDev:  0.000143051147460938,
			GLWEStdDev: 0.00000000393811205889363,

			MessageModulus: 1 << 1,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 10,
				Level: 3,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 3,
				Level: 4,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		SecretKeyStdDev: 0.00000000000000000017347234759768072,

		WindowSize: 10,
	}
)
