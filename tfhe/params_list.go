package tfhe

var (
	// ParamsBinary is a default parameter set for binary TFHE.
	ParamsBinary = ParametersLiteral[uint32]{
		LWEDimension:    812,
		GLWEDimension:   3,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.0000052851456906764125,
		GLWEStdDev: 0.0000000009315272083503367,

		BlockSize: 4,

		MessageModulus: 1 << 1,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 10,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 5,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	// ParamsBinaryCompact is a parameter set for binary TFHE
	// with OrderKeySwitchBlindRotate.
	//
	// This parameter set is slightly more compact than ParamsBinary,
	// giving a faster performance.
	ParamsBinaryCompact = ParametersLiteral[uint32]{
		LWEDimension:    747,
		GLWEDimension:   3,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.00001622209113562635,
		GLWEStdDev: 0.0000000009315272083503367,

		BlockSize: 3,

		MessageModulus: 1 << 1,

		BootstrapParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 10,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint32]{
			Base:  1 << 3,
			Level: 5,
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
		LWEDimension:    780,
		GLWEDimension:   3,
		PolyDegree:      512,
		LookUpTableSize: 512,

		LWEStdDev:  0.000009179845226680863,
		GLWEStdDev: 0.000000000019524392655548086,

		BlockSize: 3,

		MessageModulus: 1 << 2,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 17,
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
		LWEDimension:    860,
		GLWEDimension:   2,
		PolyDegree:      1024,
		LookUpTableSize: 1024,

		LWEStdDev:  0.0000023088161607134664,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 4,

		MessageModulus: 1 << 3,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 23,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 5,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint4 is a parameter set with 4 bits of message space.
	ParamsUint4 = ParametersLiteral[uint64]{
		LWEDimension:    840,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 2048,

		LWEStdDev:  0.0000032602496351120776,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 4,

		MessageModulus: 1 << 4,

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

	// ParamsUint5 is a parameter set with 5 bits of message space.
	ParamsUint5 = ParametersLiteral[uint64]{
		LWEDimension:    950,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 4096,

		LWEStdDev:  0.0000004803076706754256,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 5,

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
		LWEDimension:    1020,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 8192,

		LWEStdDev:  0.00000015380716530060473,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 6,

		MessageModulus: 1 << 6,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 7,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint7 is a parameter set with 7 bits of message space.
	ParamsUint7 = ParametersLiteral[uint64]{
		LWEDimension:    1062,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 16384,

		LWEStdDev:  0.00000007324438557758654,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 6,

		MessageModulus: 1 << 7,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 17,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 7,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	// ParamsUint8 is a parameter set with 8 bits of message space.
	ParamsUint8 = ParametersLiteral[uint64]{
		LWEDimension:    1127,
		GLWEDimension:   1,
		PolyDegree:      2048,
		LookUpTableSize: 32768,

		LWEStdDev:  0.000000023053576495153107,
		GLWEStdDev: 0.000000000000002845267479601915,

		BlockSize: 7,

		MessageModulus: 1 << 8,

		BootstrapParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 15,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 2,
			Level: 12,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
)
