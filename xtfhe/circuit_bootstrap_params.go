package xtfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// CircuitBootstrapParametersLiteral is a structure for Circuit Bootstrapping Parameters.
type CircuitBootstrapParametersLiteral[T tfhe.TorusInt] struct {
	// ManyLUTParams is a base ManyLUTParams for this CircuitBootstrapParametersLiteral.
	ManyLUTParams ManyLUTParametersLiteral[T]

	// SchemeSwitchParams is the gadget parameters for scheme switching.
	SchemeSwitchParams tfhe.GadgetParametersLiteral[T]
	// TraceKeySwitchParams is the gadget parameters for LWE to GLWE packing.
	TraceKeySwitchParams tfhe.GadgetParametersLiteral[T]
	// OutputParams is the gadget parameters for the output of circuit bootstrapping.
	OutputParams tfhe.GadgetParametersLiteral[T]
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p CircuitBootstrapParametersLiteral[T]) Compile() CircuitBootstrapParameters[T] {
	return CircuitBootstrapParameters[T]{
		manyLUTParameters: p.ManyLUTParams.Compile(),

		schemeSwitchParameters:   p.SchemeSwitchParams.Compile(),
		traceKeySwitchParameters: p.TraceKeySwitchParams.Compile(),
		outputParameters:         p.OutputParams.Compile(),
	}
}

// CircuitBootstrapParametersLiteral is a parameter set for Circuit Bootstrapping.
type CircuitBootstrapParameters[T tfhe.TorusInt] struct {
	// manyLUTParameters is a base ManyLUTParameters for this CircuitBootstrapParameters.
	manyLUTParameters ManyLUTParameters[T]

	// schemeSwitchParameters is the gadget parameters for scheme switching.
	schemeSwitchParameters tfhe.GadgetParameters[T]
	// traceKeySwitchParameters is the gadget parameters for LWE to GLWE packing.
	traceKeySwitchParameters tfhe.GadgetParameters[T]
	// outputParameters is the gadget parameters for the output of circuit bootstrapping.
	outputParameters tfhe.GadgetParameters[T]
}

// ManyLUTParams returns the base ManyLUTParams for this CircuitBootstrapParameters.
func (p CircuitBootstrapParameters[T]) ManyLUTParams() ManyLUTParameters[T] {
	return p.manyLUTParameters
}

// Params returns the base parameters for this ManyLUTParameters.
func (p CircuitBootstrapParameters[T]) Params() tfhe.Parameters[T] {
	return p.manyLUTParameters.baseParams
}

// SchemeSwitchParams returns the gadget parameters for scheme switching.
func (p CircuitBootstrapParameters[T]) SchemeSwitchParams() tfhe.GadgetParameters[T] {
	return p.schemeSwitchParameters
}

// TraceKeySwitchParams returns the gadget parameters for LWE to GLWE packing.
func (p CircuitBootstrapParameters[T]) TraceKeySwitchParams() tfhe.GadgetParameters[T] {
	return p.traceKeySwitchParameters
}

// OutputParams returns the gadget parameters for the output of circuit bootstrapping.
func (p CircuitBootstrapParameters[T]) OutputParams() tfhe.GadgetParameters[T] {
	return p.outputParameters
}
