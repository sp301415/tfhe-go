package tfhe

var (
	// ParamsUint2 ensures 2 bits of message precision.
	ParamsUint2 = ParametersLiteral[uint64]{
		LWEDimension:  656,
		GLWEDimension: 2,
		PolyDegree:    512,

		LWEStdDev:  0.000034119201269311964,
		GLWEStdDev: 0.00000004053919869756513,

		BlockSize: 2,

		MessageModulus: 1 << 2,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 8,
			Level: 2,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 4,
		},
	}

	// ParamsUint3 ensures 3 bits of message precision.
	ParamsUint3 = ParametersLiteral[uint64]{
		LWEDimension:  742,
		GLWEDimension: 2,
		PolyDegree:    1024,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		BlockSize: 2,

		MessageModulus: 1 << 3,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 3,
		},
	}

	// ParamsUint4 ensures 4 bits of message precision.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:  742,
		GLWEDimension: 1,
		PolyDegree:    2048,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		BlockSize: 2,

		MessageModulus: 1 << 4,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},
	}

	// ParamsUint5 ensures 5 bits of message precision.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:  806,
		GLWEDimension: 1,
		PolyDegree:    4096,

		LWEStdDev:  0.0000021515145918907506,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 2,

		MessageModulus: 1 << 5,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},
	}

	// ParamsUint6 ensures 5 bits of message precision.
	ParamsUint6 = ParametersLiteral[uint64]{
		LWEDimension:  914,
		GLWEDimension: 1,
		PolyDegree:    8192,

		LWEStdDev:  0.00000029804653749339636,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 2,

		MessageModulus: 1 << 6,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 4,
		},
	}

	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:  930,
		GLWEDimension: 1,
		PolyDegree:    16384,

		LWEStdDev:  0.00000022649232786295453,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 2,

		MessageModulus: 1 << 7,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 6,
		},
	}

	// ParamsUint8 ensures 8 bits of message precision.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:  1016,
		GLWEDimension: 1,
		PolyDegree:    32768,

		LWEStdDev:  0.0000000460803851108693,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		BlockSize: 2,

		MessageModulus: 1 << 8,

		BootstrapParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 5,
		},
	}
)
