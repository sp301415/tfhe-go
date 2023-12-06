package tfhe

var (
	// ParamsUint2 ensures 2 bits of message precision.
	ParamsUint2 = ParametersLiteral[uint64]{
		LWEDimension:  656,
		GLWEDimension: 2,
		PolyDegree:    512,

		LWEStdDev:  0.000034119201269311964,
		GLWEStdDev: 0.00000004053919869756513,

		BlockSize: 4,

		MessageModulus: 1 << 2,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 4,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint3 ensures 3 bits of message precision.
	ParamsUint3 = ParametersLiteral[uint64]{
		LWEDimension:  740,
		GLWEDimension: 2,
		PolyDegree:    1024,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		BlockSize: 5,

		MessageModulus: 1 << 3,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 3,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint4 ensures 4 bits of message precision.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:  740,
		GLWEDimension: 1,
		PolyDegree:    2048,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		BlockSize: 5,

		MessageModulus: 1 << 4,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint5 ensures 5 bits of message precision.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:  804,
		GLWEDimension: 1,
		PolyDegree:    4096,

		LWEStdDev:  0.0000021515145918907506,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 6,

		MessageModulus: 1 << 5,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint6 ensures 6 bits of message precision.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:  912,
		GLWEDimension: 1,
		PolyDegree:    8192,

		LWEStdDev:  0.00000029804653749339636,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 8,

		MessageModulus: 1 << 6,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 4,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint7 ensures 7 bits of message precision.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:  928,
		GLWEDimension: 1,
		PolyDegree:    16384,

		LWEStdDev:  0.00000022649232786295453,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 8,

		MessageModulus: 1 << 7,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 6,
		},

		UseLargeLWEEntities: true,
	}

	// ParamsUint8 ensures 8 bits of message precision.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:  1017,
		GLWEDimension: 1,
		PolyDegree:    32768,

		LWEStdDev:  0.0000000460803851108693,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 9,

		MessageModulus: 1 << 8,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 5,
		},

		UseLargeLWEEntities: true,
	}
)
