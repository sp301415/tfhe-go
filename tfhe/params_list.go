package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension:    687,
		GLWERank:        2,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.00002024849643226141,
		GLWEStdDev: 0.0000000444843247619562,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BlindRotateParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryCompact is a parameter set for binary TFHE
	// with OrderKeySwitchBlindRotate.
	ParamsBinaryCompact = ParametersLiteral[uint32]{
		LWEDimension:    687,
		GLWERank:        2,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.00002024849643226141,
		GLWEStdDev: 0.0000000444843247619562,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BlindRotateParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsBinaryOriginal is a parameter set from the original C++ TFHE library.
	ParamsBinaryOriginal = ParametersLiteral[uint32]{
		LWEDimension: 630,
		GLWERank:     1,
		PolyDegree:   1024,

		LWEStdDev:  0.000030517578125,
		GLWEStdDev: 0.0000000298023223876953125,

		MessageModulus: 1 << 1,

		BlindRotateParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 7,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 2,
			Level: 8,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsUint2 is a parameter set with 2 bits of message space.
	ParamsUint2 = ParametersLiteral[uint64]{
		LWEDimension:    687,
		GLWERank:        3,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.000020524870466164442,
		GLWEStdDev: 0.000000000003916278475726331,

		BlockSize: 3,

		MessageModulus: 1 << 2,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 18,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint3 is a parameter set with 3 bits of message space.
	ParamsUint3 = ParametersLiteral[uint64]{
		LWEDimension:    804,
		GLWERank:        2,
		PolyDegree:      1024,
		LookUpTableSize: 1024,

		LWEStdDev:  0.000002433797421598353,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 4,

		MessageModulus: 1 << 3,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 2,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint4 is a parameter set with 4 bits of message space.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:    804,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048,

		LWEStdDev:  0.000002433797421598353,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 4,

		MessageModulus: 1 << 4,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint5 is a parameter set with 5 bits of message space.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:    978,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048,

		LWEStdDev:  0.00000010213207908022988,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 6,

		MessageModulus: 1 << 5,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint6 is a parameter set with 6 bits of message space.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:    1071,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 4096,

		LWEStdDev:  0.000000018754870581971254,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 7,

		MessageModulus: 1 << 6,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint7 is a parameter set with 7 bits of message space.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 8192,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 8,

		MessageModulus: 1 << 7,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint8 is a parameter set with 8 bits of message space.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 18432,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 8,

		MessageModulus: 1 << 8,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
)
