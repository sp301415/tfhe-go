package xtfhe

import "github.com/sp301415/tfhe-go/tfhe"

var (
	// ParamsSanitizeBinary is the default parameters for sanitizing binary TFHE ciphertexts.
	ParamsSanitizeBinary = SanitizationParametersLiteral[uint64]{
		BaseParams: tfhe.ParametersLiteral[uint64]{
			LWEDimension: 612,
			GLWERank:     1,
			PolyRank:     2048,

			BlockSize: 1,

			MessageModulus: 1 << 1,

			LWEStdDev:  0.00007905932600864546,
			GLWEStdDev: 0.0000000000000003472576015484159,

			BlindRotateParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 11,
				Level: 3,
			},
			KeySwitchParams: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 3,
				Level: 4,
			},

			BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
		},

		RandSigma:    0.00000000000000008449279779330043,
		RandTau:      0.000000000570793820594853,
		LinEvalSigma: 0.000000000000000012106655611491527,
		LinEvalTau:   0.008864348118988643,
	}
)
