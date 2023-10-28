//go:build amd64

TEXT ·mulAndScaleAVX2(SB), $0-56
	VMOVUPD x+0(FP), X0
	VMOVUPD y+16(FP), X1

	// Complex multiplication
	VSHUFPD $0b01, X1, X1, X2
	VSHUFPD $0b11, X0, X0, X3
	VSHUFPD $0b00, X0, X0, X4

	VMULPD X2, X3, X5
	VFMADDSUB231PD X1, X4, X5

	// Round and negate
	VROUNDPD $0, X5, X6
	VSUBPD X6, X5, X5

	// Multiply and return
	MOVDDUP T+32(FP), X7
	VMULPD X5, X7, X5

	VMOVUPD X5, ret+40(FP)
	RET
