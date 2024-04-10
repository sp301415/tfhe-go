package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension:    723,
		GLWEDimension:   2,
		PolyDegree:      512,
		PolyLargeDegree: 512,

		LWEStdDev:  0.000013071021089943935,
		GLWEStdDev: 0.00000004990272175010415,

		BlockSize: 3,

		MessageModulus: 1 << 2,

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
	//
	// This parameter set is slightly more compact than ParamsBinary,
	// giving a faster performance.
	ParamsBinaryCompact = ParametersLiteral[uint32]{
		LWEDimension:    664,
		GLWEDimension:   2,
		PolyDegree:      512,
		PolyLargeDegree: 512,

		LWEStdDev:  0.0000380828292345977,
		GLWEStdDev: 0.00000004990272175010415,

		BlockSize: 2,

		MessageModulus: 1 << 2,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 4,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsBinaryOriginal is a parameter set from the original C++ TFHE library.
	ParamsBinaryOriginal = ParametersLiteral[uint32]{
		LWEDimension:    630,
		GLWEDimension:   1,
		PolyDegree:      1024,
		PolyLargeDegree: 1024,

		LWEStdDev:  0.000030517578125,
		GLWEStdDev: 0.0000000298023223876953125,

		BlockSize: 1,

		MessageModulus: 1 << 2,

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
		LWEDimension:    700,
		GLWEDimension:   3,
		PolyDegree:      512,
		PolyLargeDegree: 512,

		LWEStdDev:  1.9974501253932986e-05,
		GLWEStdDev: 3.966608917163306e-12,

		BlockSize: 2,

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
		LWEDimension:    759,
		GLWEDimension:   2,
		PolyDegree:      1024,
		PolyLargeDegree: 1024,

		LWEStdDev:  6.607570143466592e-06,
		GLWEStdDev: 3.1529322391500584e-16,

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
		LWEDimension:    762,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 2048,

		LWEStdDev:  6.36835566258815e-06,
		GLWEStdDev: 3.1529322391500584e-16,

		BlockSize: 3,

		MessageModulus: 1 << 4,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint5 is a parameter set with 5 bits of message space.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:    852,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 4096,

		LWEStdDev:  1.2571599559956785e-06,
		GLWEStdDev: 3.1529322391500584e-16,

		BlockSize: 4,

		MessageModulus: 1 << 5,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 4,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint6 is a parameter set with 6 bits of message space.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:    935,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 8192,

		LWEStdDev:  2.77202526552345e-07,
		GLWEStdDev: 3.1529322391500584e-16,

		BlockSize: 5,

		MessageModulus: 1 << 6,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 4,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint7 is a parameter set with 7 bits of message space.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:    950,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 16384,

		LWEStdDev:  2.0638655780656257e-07,
		GLWEStdDev: 3.1529322391500584e-16,

		BlockSize: 5,

		MessageModulus: 1 << 7,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 6,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint8 is a parameter set with 8 bits of message space.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:    1032,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 32768,

		LWEStdDev:  4.305923848218434e-08,
		GLWEStdDev: 3.1529322391500584e-16,

		BlockSize: 6,

		MessageModulus: 1 << 8,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 5,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
)
