package mktfhe

import (
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

// polyFourierDecomposedBuffer returns the fourierPolyDecomposed buffer of Evaluator.
// if len(fourierPolyDecomposed) >= Level, it returns the subslice of the buffer.
// otherwise, it extends the buffer of the Evaluator and returns it.
func (e *Evaluator[T]) polyFourierDecomposedBuffer(gadgetParams tfhe.GadgetParameters[T]) []poly.FourierPoly {
	if len(e.buffer.polyFourierDecomposed) >= gadgetParams.Level() {
		return e.buffer.polyFourierDecomposed[:gadgetParams.Level()]
	}

	oldLen := len(e.buffer.polyFourierDecomposed)
	e.buffer.polyFourierDecomposed = append(e.buffer.polyFourierDecomposed, make([]poly.FourierPoly, gadgetParams.Level()-oldLen)...)
	for i := oldLen; i < gadgetParams.Level(); i++ {
		e.buffer.polyFourierDecomposed[i] = e.BaseSingleKeyEvaluator.FourierEvaluator.NewFourierPoly()
	}
	return e.buffer.polyFourierDecomposed
}
