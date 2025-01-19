package xtfhe

import (
	"github.com/sp301415/tfhe-go/tfhe"
)

// CircuitBootstrapParametersLiteral is a structure for Circuit Bootstrapping Parameters.
type CircuitBootstrapParametersLiteral[T tfhe.TorusInt] struct {
	// ManyLUTParametersLiteral is a base ManyLUTParametersLiteral for this CircuitBootstrapParametersLiteral.
	ManyLUTParametersLiteral ManyLUTParametersLiteral[T]

	// SchemeSwitchParametersLiteral is the gadget parameters for scheme switching.
	SchemeSwitchParametersLiteral tfhe.GadgetParametersLiteral[T]
	// TraceKeySwitchParametersLiteral is the gadget parameters for LWE to GLWE packing.
	TraceKeySwitchParametersLiteral tfhe.GadgetParametersLiteral[T]
	// OutputParametersLiteral is the gadget parameters for the output of circuit bootstrapping.
	OutputParametersLiteral tfhe.GadgetParametersLiteral[T]
}

// Compile transforms ParametersLiteral to read-only Parameters.
// If there is any invalid parameter in the literal, it panics.
// Default parameters are guaranteed to be compiled without panics.
func (p CircuitBootstrapParametersLiteral[T]) Compile() CircuitBootstrapParameters[T] {
	return CircuitBootstrapParameters[T]{
		manyLUTParameters: p.ManyLUTParametersLiteral.Compile(),

		schemeSwitchParameters:   p.SchemeSwitchParametersLiteral.Compile(),
		traceKeySwitchParameters: p.TraceKeySwitchParametersLiteral.Compile(),
		outputParameters:         p.OutputParametersLiteral.Compile(),
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

// ManyLUTParameters returns the base ManyLUTParameters for this CircuitBootstrapParameters.
func (p CircuitBootstrapParameters[T]) ManyLUTParameters() ManyLUTParameters[T] {
	return p.manyLUTParameters
}

// BaseParameters returns the base parameter set for this ManyLUTParameters.
func (p CircuitBootstrapParameters[T]) BaseParameters() tfhe.Parameters[T] {
	return p.manyLUTParameters.baseParameters
}

// SchemeSwitchParameters returns the gadget parameters for scheme switching.
func (p CircuitBootstrapParameters[T]) SchemeSwitchParameters() tfhe.GadgetParameters[T] {
	return p.schemeSwitchParameters
}

// TraceKeySwitchParameters returns the gadget parameters for LWE to GLWE packing.
func (p CircuitBootstrapParameters[T]) TraceKeySwitchParameters() tfhe.GadgetParameters[T] {
	return p.traceKeySwitchParameters
}

// OutputParameters returns the gadget parameters for the output of circuit bootstrapping.
func (p CircuitBootstrapParameters[T]) OutputParameters() tfhe.GadgetParameters[T] {
	return p.outputParameters
}
