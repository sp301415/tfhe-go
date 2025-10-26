package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension: 687,
		GLWERank:     2,
		PolyRank:     512,
		LUTSize:      512,

		LWEStdDev:  0.00002120846893069971872305794214,
		GLWEStdDev: 0.00000002685935683878752834630074,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BlindRotateParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 4,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryCompact is a parameter set for binary TFHE
	// with OrderKeySwitchBlindRotate.
	ParamsBinaryCompact = ParametersLiteral[uint32]{
		LWEDimension: 687,
		GLWERank:     2,
		PolyRank:     512,
		LUTSize:      512,

		LWEStdDev:  0.00002120846893069971872305794214,
		GLWEStdDev: 0.00000002685935683878752834630074,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BlindRotateParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsBinaryOriginal is a parameter set from the original C++ TFHE library.
	ParamsBinaryOriginal = ParametersLiteral[uint32]{
		LWEDimension: 630,
		GLWERank:     1,
		PolyRank:     1024,

		LWEStdDev:  0.000030517578125,
		GLWEStdDev: 0.0000000298023223876953125,

		MessageModulus: 1 << 1,

		BlindRotateParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 7,
			Level: 3,
		},
		KeySwitchParams: GadgetParametersLiteral[uint32]{
			Base:  1 << 2,
			Level: 8,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsUint2 is a parameter set with 2 bits of message space.
	ParamsUint2 = ParametersLiteral[uint64]{
		LWEDimension: 687,
		GLWERank:     3,
		PolyRank:     512,
		LUTSize:      512,

		LWEStdDev:  0.00002120846893069971872305794214,
		GLWEStdDev: 0.00000000000231841227527049948463,

		BlockSize: 3,

		MessageModulus: 1 << 2,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 18,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint3 is a parameter set with 3 bits of message space.
	ParamsUint3 = ParametersLiteral[uint64]{
		LWEDimension: 820,
		GLWERank:     2,
		PolyRank:     1024,
		LUTSize:      1024,

		LWEStdDev:  0.00000251676160959795544987084234,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 4,

		MessageModulus: 1 << 3,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 2,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint4 is a parameter set with 4 bits of message space.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension: 820,
		GLWERank:     1,
		PolyRank:     2048,
		LUTSize:      2048,

		LWEStdDev:  0.00000251676160959795544987084234,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 4,

		MessageModulus: 1 << 4,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint5 is a parameter set with 5 bits of message space.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension: 1071,
		GLWERank:     1,
		PolyRank:     2048,
		LUTSize:      2048,

		LWEStdDev:  0.00000007088226765410429399593757,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 7,

		MessageModulus: 1 << 5,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint6 is a parameter set with 6 bits of message space.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension: 1071,
		GLWERank:     1,
		PolyRank:     2048,
		LUTSize:      4096,

		LWEStdDev:  0.00000007088226765410429399593757,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 7,

		MessageModulus: 1 << 6,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint7 is a parameter set with 7 bits of message space.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension: 1160,
		GLWERank:     1,
		PolyRank:     2048,
		LUTSize:      8192,

		LWEStdDev:  0.00000001966220007498402695211596,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 8,

		MessageModulus: 1 << 7,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint8 is a parameter set with 8 bits of message space.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension: 1160,
		GLWERank:     1,
		PolyRank:     2048,
		LUTSize:      18432,

		LWEStdDev:  0.00000001966220007498402695211596,
		GLWEStdDev: 0.00000000000000022204460492503131,

		BlockSize: 8,

		MessageModulus: 1 << 8,

		BlindRotateParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParams: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
)
