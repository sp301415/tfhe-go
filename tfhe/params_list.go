package tfhe

var (
	// ParamsMessage4Carry0 ensures 4 bit of message space and 0 bit of carry space.
	ParamsMessage4Carry0 = ParametersLiteral[uint64]{
		LWEDimension:  742,
		GLWEDimension: 1,
		PolyDegree:    2048,

		LWEStdDev:  0.000007069849454709433,
		GLWEStdDev: 0.00000000000000029403601535432533,

		MessageModulus: 1 << 4,
		CarryModulus:   1 << 0,

		PBSParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 5,
		},
	}

	// ParamsMessage8Carry0 ensures 8 bit of message space and 0 bit of carry space.
	ParamsMessage8Carry0 = ParametersLiteral[uint64]{
		LWEDimension:  1017,
		GLWEDimension: 1,
		PolyDegree:    32768,

		LWEStdDev:  0.0000000460803851108693,
		GLWEStdDev: 0.0000000000000000002168404344971009,

		MessageModulus: 1 << 8,
		CarryModulus:   1 << 0,

		PBSParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: DecompositionParametersLiteral[uint64]{
			Base:  1 << 4,
			Level: 5,
		},
	}
)
