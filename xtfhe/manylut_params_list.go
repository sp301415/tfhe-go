package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsBinaryLUT2 is a default parameter set for binary TFHE with 2 LUTs.
	ParamsBinaryLUT2 = ManyLUTParametersLiteral[uint32]{
		BaseParams: tfhe.ParametersLiteral[uint32]{
			LWEDimension: 687,
			GLWERank:     1,
			PolyRank:     1024,
			LUTSize:      1024,

			LWEStdDev:  0.00002024849643226141,
			GLWEStdDev: 0.0000000444843247619562,

			BlockSize: 3,

			MessageModulus: 1 << 1,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint32]{
				Base:  1 << 6,
				Level: 3,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint32]{
				Base:  1 << 3,
				Level: 4,
			},

			BootstrapOrder: tfhe.OrderBlindRotateKeySwitch,
		},

		LUTCount: 2,
	}

	// ParamsBinaryCompactLUT2 is a parameter set for binary TFHE
	// with OrderKeySwitchBlindRotate with 2 LUTs.
	ParamsBinaryCompactLUT2 = ManyLUTParametersLiteral[uint32]{
		BaseParams: tfhe.ParametersLiteral[uint32]{
			LWEDimension: 687,
			GLWERank:     1,
			PolyRank:     1024,
			LUTSize:      1024,

			LWEStdDev:  0.00002024849643226141,
			GLWEStdDev: 0.0000000444843247619562,

			BlockSize: 3,

			MessageModulus: 1 << 1,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint32]{
				Base:  1 << 6,
				Level: 3,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint32]{
				Base:  1 << 4,
				Level: 3,
			},

			BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
		},

		LUTCount: 2,
	}

	// ParamsUint2LUT4 is a parameter set with 2 bits of message space with 4 LUTs.
	ParamsUint2LUT4 = ManyLUTParametersLiteral[uint64]{
		BaseParams: tfhe.ParametersLiteral[uint64]{
			LWEDimension: 804,
			GLWERank:     1,
			PolyRank:     2048,
			LUTSize:      2048,

			LWEStdDev:  0.000002433797421598353,
			GLWEStdDev: 0.0000000000000003472576015484159,

			BlockSize: 4,

			MessageModulus: 1 << 2,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 23,
				Level: 1,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 6,
				Level: 2,
			},

			BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
		},

		LUTCount: 4,
	}

	// ParamsUint3LUT2 is a parameter set with 3 bits of message space with 2 LUTs.
	ParamsUint3LUT2 = ManyLUTParametersLiteral[uint64]{
		BaseParams: tfhe.ParametersLiteral[uint64]{

			LWEDimension: 804,
			GLWERank:     1,
			PolyRank:     2048,
			LUTSize:      2048,

			LWEStdDev:  0.000002433797421598353,
			GLWEStdDev: 0.0000000000000003472576015484159,

			BlockSize: 4,

			MessageModulus: 1 << 3,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 23,
				Level: 1,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 6,
				Level: 2,
			},

			BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
		},

		LUTCount: 2,
	}
)
