package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension:    687,
		GLWEDimension:   2,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.000020980834960937642,
		GLWEStdDev: 0.0000000465661287309906,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 4,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryCompact is a parameter set for binary TFHE
	// with OrderKeySwitchBlindRotate.
	ParamsBinaryCompact = ParametersLiteral[uint32]{
		LWEDimension:    687,
		GLWEDimension:   2,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.000020980834960937642,
		GLWEStdDev: 0.0000000465661287309906,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
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
		LWEDimension:    630,
		GLWEDimension:   1,
		PolyDegree:      1024,
		LookUpTableSize: 1024,

		LWEStdDev:  0.000030517578125,
		GLWEStdDev: 0.0000000298023223876953125,

		BlockSize: 1,

		MessageModulus: 1 << 1,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
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
		GLWEDimension:   3,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.000020980834960937642,
		GLWEStdDev: 0.000000000004320100050261828,

		BlockSize: 3,

		MessageModulus: 1 << 2,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
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
		LWEDimension:    756,
		GLWEDimension:   2,
		PolyDegree:      1024,
		LookUpTableSize: 1024,

		LWEStdDev:  0.0000060796737670900386,
		GLWEStdDev: 0.0000000000000003887948990533005,

		BlockSize: 3,

		MessageModulus: 1 << 3,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint4 is a parameter set with 4 bits of message space.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:    808,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 2048,

		LWEStdDev:  0.0000023841857910158334,
		GLWEStdDev: 0.0000000000000003887948990533005,

		BlockSize: 4,

		MessageModulus: 1 << 4,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
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
		LWEDimension:    844,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 4096,

		LWEStdDev:  0.0000012218952178957204,
		GLWEStdDev: 0.00000000000000031529322391500584,

		BlockSize: 4,

		MessageModulus: 1 << 5,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint6 is a parameter set with 6 bits of message space.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:    905,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 6144,

		LWEStdDev:  0.0000004097819328310259,
		GLWEStdDev: 0.00000000000000031529322391500584,

		BlockSize: 5,

		MessageModulus: 1 << 6,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint7 is a parameter set with 7 bits of message space.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:    978,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 10240,

		LWEStdDev:  0.00000010803341865561196,
		GLWEStdDev: 0.00000000000000031529322391500584,

		BlockSize: 6,

		MessageModulus: 1 << 7,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint8 is a parameter set with 8 bits of message space.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:    1071,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 22528,

		LWEStdDev:  0.000000020023435354449556,
		GLWEStdDev: 0.00000000000000031529322391500584,

		BlockSize: 7,

		MessageModulus: 1 << 8,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
)
