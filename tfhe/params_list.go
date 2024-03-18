package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension:    723,
		GLWEDimension:   2,
		PolyDegree:      512,
		PolyLargeDegree: 512,

		LWEStdDev:  0.000013071021089943935 * (1 << 32),
		GLWEStdDev: 0.00000004990272175010415 * (1 << 32),

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

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint2 is a parameter set with 2 bits of message space.
	ParamsUint2 = ParametersLiteral[uint64]{
		LWEDimension:    656,
		GLWEDimension:   2,
		PolyDegree:      512,
		PolyLargeDegree: 512,

		LWEStdDev:  0.000034119201269311964 * (1 << 64),
		GLWEStdDev: 0.00000004053919869756513 * (1 << 64),

		BlockSize: 2,

		MessageModulus: 1 << 2,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 6,
			Level: 3,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 6,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint3 is a parameter set with 3 bits of message space.
	ParamsUint3 = ParametersLiteral[uint64]{
		LWEDimension:    744,
		GLWEDimension:   2,
		PolyDegree:      1024,
		PolyLargeDegree: 1024,

		LWEStdDev:  0.000007069849454709433 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

		BlockSize: 3,

		MessageModulus: 1 << 3,

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

	// ParamsUint4 is a parameter set with 4 bits of message space.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:    744,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 2048,

		LWEStdDev:  0.000007069849454709433 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

		BlockSize: 3,

		MessageModulus: 1 << 4,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 7,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint5 is a parameter set with 5 bits of message space.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:    808,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 4096,

		LWEStdDev:  0.0000021515145918907506 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

		BlockSize: 4,

		MessageModulus: 1 << 5,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint6 is a parameter set with 6 bits of message space.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:    915,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 8192,

		LWEStdDev:  0.00000029804653749339636 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

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
		LWEDimension:    930,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 16384,

		LWEStdDev:  0.00000022649232786295453 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

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
		LWEDimension:    1020,
		GLWEDimension:   1,
		PolyDegree:      2048,
		PolyLargeDegree: 32768,

		LWEStdDev:  0.0000000460803851108693 * (1 << 64),
		GLWEStdDev: 0.00000000000000029403601535432533 * (1 << 64),

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
