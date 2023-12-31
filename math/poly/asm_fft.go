//go:build !(amd64 && !purego)

package poly

import (
	"math"
)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs []float64, wNj []complex128) {
	N := len(coeffs)

	// First Loop
	for j := 0; j < N/2; j += 8 {
		Ur0 := coeffs[j+0]
		Ur1 := coeffs[j+1]
		Ur2 := coeffs[j+2]
		Ur3 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Ui1 := coeffs[j+5]
		Ui2 := coeffs[j+6]
		Ui3 := coeffs[j+7]

		Vr0 := coeffs[j+N/2+0]
		Vr1 := coeffs[j+N/2+1]
		Vr2 := coeffs[j+N/2+2]
		Vr3 := coeffs[j+N/2+3]

		Vi0 := coeffs[j+N/2+4]
		Vi1 := coeffs[j+N/2+5]
		Vi2 := coeffs[j+N/2+6]
		Vi3 := coeffs[j+N/2+7]

		coeffs[j+0] = Ur0 + Vr0
		coeffs[j+1] = Ur1 + Vr1
		coeffs[j+2] = Ur2 + Vr2
		coeffs[j+3] = Ur3 + Vr3

		coeffs[j+4] = Ui0 + Vi0
		coeffs[j+5] = Ui1 + Vi1
		coeffs[j+6] = Ui2 + Vi2
		coeffs[j+7] = Ui3 + Vi3

		coeffs[j+N/2+0] = Ur0 - Vr0
		coeffs[j+N/2+1] = Ur1 - Vr1
		coeffs[j+N/2+2] = Ur2 - Vr2
		coeffs[j+N/2+3] = Ur3 - Vr3

		coeffs[j+N/2+4] = Ui0 - Vi0
		coeffs[j+N/2+5] = Ui1 - Vi1
		coeffs[j+N/2+6] = Ui2 - Vi2
		coeffs[j+N/2+7] = Ui3 - Vi3
	}

	// Main Loop
	t := N >> 1
	for m := 4; m < N>>2; m <<= 1 {
		t >>= 1
		h := m >> 1
		for i := 0; i < h; i++ {
			j1 := i * t << 1
			j2 := j1 + t

			Wr := real(wNj[h+i])
			Wi := imag(wNj[h+i])
			for j := j1; j < j2; j += 8 {
				Ur0 := coeffs[j+0]
				Ur1 := coeffs[j+1]
				Ur2 := coeffs[j+2]
				Ur3 := coeffs[j+3]

				Ui0 := coeffs[j+4]
				Ui1 := coeffs[j+5]
				Ui2 := coeffs[j+6]
				Ui3 := coeffs[j+7]

				Vr0 := coeffs[j+t+0]
				Vr1 := coeffs[j+t+1]
				Vr2 := coeffs[j+t+2]
				Vr3 := coeffs[j+t+3]

				Vi0 := coeffs[j+t+4]
				Vi1 := coeffs[j+t+5]
				Vi2 := coeffs[j+t+6]
				Vi3 := coeffs[j+t+7]

				Vr0W := Vr0*Wr - Vi0*Wi
				Vr1W := Vr1*Wr - Vi1*Wi
				Vr2W := Vr2*Wr - Vi2*Wi
				Vr3W := Vr3*Wr - Vi3*Wi

				Vi0W := Vr0*Wi + Vi0*Wr
				Vi1W := Vr1*Wi + Vi1*Wr
				Vi2W := Vr2*Wi + Vi2*Wr
				Vi3W := Vr3*Wi + Vi3*Wr

				coeffs[j+0] = Ur0 + Vr0W
				coeffs[j+1] = Ur1 + Vr1W
				coeffs[j+2] = Ur2 + Vr2W
				coeffs[j+3] = Ur3 + Vr3W

				coeffs[j+4] = Ui0 + Vi0W
				coeffs[j+5] = Ui1 + Vi1W
				coeffs[j+6] = Ui2 + Vi2W
				coeffs[j+7] = Ui3 + Vi3W

				coeffs[j+t+0] = Ur0 - Vr0W
				coeffs[j+t+1] = Ur1 - Vr1W
				coeffs[j+t+2] = Ur2 - Vr2W
				coeffs[j+t+3] = Ur3 - Vr3W

				coeffs[j+t+4] = Ui0 - Vi0W
				coeffs[j+t+5] = Ui1 - Vi1W
				coeffs[j+t+6] = Ui2 - Vi2W
				coeffs[j+t+7] = Ui3 - Vi3W
			}
		}
	}

	// Stride 2
	for i, j := 0, 0; j < N; i, j = i+1, j+8 {
		Wr := real(wNj[i+(N>>3)])
		Wi := imag(wNj[i+(N>>3)])

		Ur0 := coeffs[j+0]
		Ur1 := coeffs[j+1]
		Vr0 := coeffs[j+2]
		Vr1 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Ui1 := coeffs[j+5]
		Vi0 := coeffs[j+6]
		Vi1 := coeffs[j+7]

		Vr0W := Vr0*Wr - Vi0*Wi
		Vr1W := Vr1*Wr - Vi1*Wi
		Vi0W := Vr0*Wi + Vi0*Wr
		Vi1W := Vr1*Wi + Vi1*Wr

		coeffs[j+0] = Ur0 + Vr0W
		coeffs[j+1] = Ur1 + Vr1W
		coeffs[j+2] = Ur0 - Vr0W
		coeffs[j+3] = Ur1 - Vr1W

		coeffs[j+4] = Ui0 + Vi0W
		coeffs[j+5] = Ui1 + Vi1W
		coeffs[j+6] = Ui0 - Vi0W
		coeffs[j+7] = Ui1 - Vi1W
	}

	// Stride 1
	for i, j := 0, 0; j < N; i, j = i+2, j+8 {
		Wr0 := real(wNj[i+(N>>2)])
		Wi0 := imag(wNj[i+(N>>2)])
		Wr1 := real(wNj[i+(N>>2)+1])
		Wi1 := imag(wNj[i+(N>>2)+1])

		Ur0 := coeffs[j+0]
		Vr0 := coeffs[j+1]
		Ur1 := coeffs[j+2]
		Vr1 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Vi0 := coeffs[j+5]
		Ui1 := coeffs[j+6]
		Vi1 := coeffs[j+7]

		Vr0W := Vr0*Wr0 - Vi0*Wi0
		Vi0W := Vr0*Wi0 + Vi0*Wr0
		Vr1W := Vr1*Wr1 - Vi1*Wi1
		Vi1W := Vr1*Wi1 + Vi1*Wr1

		coeffs[j+0] = Ur0 + Vr0W
		coeffs[j+1] = Ur0 - Vr0W
		coeffs[j+2] = Ur1 + Vr1W
		coeffs[j+3] = Ur1 - Vr1W

		coeffs[j+4] = Ui0 + Vi0W
		coeffs[j+5] = Ui0 - Vi0W
		coeffs[j+6] = Ui1 + Vi1W
		coeffs[j+7] = Ui1 - Vi1W
	}
}

// InvfftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs []float64, wNjInv []complex128) {
	N := len(coeffs)

	// Stride 1
	for i, j := 0, 0; j < N; i, j = i+2, j+8 {
		Wr0 := real(wNjInv[i])
		Wi0 := imag(wNjInv[i])
		Wr1 := real(wNjInv[i+1])
		Wi1 := imag(wNjInv[i+1])

		Ur0 := coeffs[j+0]
		Vr0 := coeffs[j+1]
		Ur1 := coeffs[j+2]
		Vr1 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Vi0 := coeffs[j+5]
		Ui1 := coeffs[j+6]
		Vi1 := coeffs[j+7]

		coeffs[j+0] = Ur0 + Vr0
		coeffs[j+2] = Ur1 + Vr1

		coeffs[j+4] = Ui0 + Vi0
		coeffs[j+6] = Ui1 + Vi1

		UVr0 := Ur0 - Vr0
		UVi0 := Ui0 - Vi0
		UVr1 := Ur1 - Vr1
		UVi1 := Ui1 - Vi1

		UVr0W := UVr0*Wr0 - UVi0*Wi0
		UVi0W := UVr0*Wi0 + UVi0*Wr0
		UVr1W := UVr1*Wr1 - UVi1*Wi1
		UVi1W := UVr1*Wi1 + UVi1*Wr1

		coeffs[j+1] = UVr0W
		coeffs[j+3] = UVr1W

		coeffs[j+5] = UVi0W
		coeffs[j+7] = UVi1W
	}

	// Stride 2
	for i, j := 0, 0; j < N; i, j = i+1, j+8 {
		Wr := real(wNjInv[i+(N>>2)])
		Wi := imag(wNjInv[i+(N>>2)])

		Ur0 := coeffs[j+0]
		Ur1 := coeffs[j+1]
		Vr0 := coeffs[j+2]
		Vr1 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Ui1 := coeffs[j+5]
		Vi0 := coeffs[j+6]
		Vi1 := coeffs[j+7]

		coeffs[j+0] = Ur0 + Vr0
		coeffs[j+1] = Ur1 + Vr1

		coeffs[j+4] = Ui0 + Vi0
		coeffs[j+5] = Ui1 + Vi1

		UVr0 := Ur0 - Vr0
		UVr1 := Ur1 - Vr1
		UVi0 := Ui0 - Vi0
		UVi1 := Ui1 - Vi1

		UVr0W := UVr0*Wr - UVi0*Wi
		UVr1W := UVr1*Wr - UVi1*Wi
		UVi0W := UVr0*Wi + UVi0*Wr
		UVi1W := UVr1*Wi + UVi1*Wr

		coeffs[j+2] = UVr0W
		coeffs[j+3] = UVr1W

		coeffs[j+6] = UVi0W
		coeffs[j+7] = UVi1W
	}

	// Main Loop
	t := 8
	k := (N >> 2) + (N >> 3)
	for m := N / 8; m > 2; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t

			Wr := real(wNjInv[k+i])
			Wi := imag(wNjInv[k+i])
			for j := j1; j < j2; j += 8 {
				Ur0 := coeffs[j+0]
				Ur1 := coeffs[j+1]
				Ur2 := coeffs[j+2]
				Ur3 := coeffs[j+3]

				Ui0 := coeffs[j+4]
				Ui1 := coeffs[j+5]
				Ui2 := coeffs[j+6]
				Ui3 := coeffs[j+7]

				Vr0 := coeffs[j+t+0]
				Vr1 := coeffs[j+t+1]
				Vr2 := coeffs[j+t+2]
				Vr3 := coeffs[j+t+3]

				Vi0 := coeffs[j+t+4]
				Vi1 := coeffs[j+t+5]
				Vi2 := coeffs[j+t+6]
				Vi3 := coeffs[j+t+7]

				coeffs[j+0] = Ur0 + Vr0
				coeffs[j+1] = Ur1 + Vr1
				coeffs[j+2] = Ur2 + Vr2
				coeffs[j+3] = Ur3 + Vr3

				coeffs[j+4] = Ui0 + Vi0
				coeffs[j+5] = Ui1 + Vi1
				coeffs[j+6] = Ui2 + Vi2
				coeffs[j+7] = Ui3 + Vi3

				UVr0 := Ur0 - Vr0
				UVr1 := Ur1 - Vr1
				UVr2 := Ur2 - Vr2
				UVr3 := Ur3 - Vr3

				UVi0 := Ui0 - Vi0
				UVi1 := Ui1 - Vi1
				UVi2 := Ui2 - Vi2
				UVi3 := Ui3 - Vi3

				UVr0W := UVr0*Wr - UVi0*Wi
				UVr1W := UVr1*Wr - UVi1*Wi
				UVr2W := UVr2*Wr - UVi2*Wi
				UVr3W := UVr3*Wr - UVi3*Wi

				UVi0W := UVr0*Wi + UVi0*Wr
				UVi1W := UVr1*Wi + UVi1*Wr
				UVi2W := UVr2*Wi + UVi2*Wr
				UVi3W := UVr3*Wi + UVi3*Wr

				coeffs[j+t+0] = UVr0W
				coeffs[j+t+1] = UVr1W
				coeffs[j+t+2] = UVr2W
				coeffs[j+t+3] = UVr3W

				coeffs[j+t+4] = UVi0W
				coeffs[j+t+5] = UVi1W
				coeffs[j+t+6] = UVi2W
				coeffs[j+t+7] = UVi3W
			}
			j1 += t << 1
		}
		t <<= 1
		k += h
	}

	// Last Loop
	for j := 0; j < N/2; j += 8 {
		Ur0 := coeffs[j+0]
		Ur1 := coeffs[j+1]
		Ur2 := coeffs[j+2]
		Ur3 := coeffs[j+3]

		Ui0 := coeffs[j+4]
		Ui1 := coeffs[j+5]
		Ui2 := coeffs[j+6]
		Ui3 := coeffs[j+7]

		Vr0 := coeffs[j+N/2+0]
		Vr1 := coeffs[j+N/2+1]
		Vr2 := coeffs[j+N/2+2]
		Vr3 := coeffs[j+N/2+3]

		Vi0 := coeffs[j+N/2+4]
		Vi1 := coeffs[j+N/2+5]
		Vi2 := coeffs[j+N/2+6]
		Vi3 := coeffs[j+N/2+7]

		coeffs[j+0] = Ur0 + Vr0
		coeffs[j+1] = Ur1 + Vr1
		coeffs[j+2] = Ur2 + Vr2
		coeffs[j+3] = Ur3 + Vr3

		coeffs[j+4] = Ui0 + Vi0
		coeffs[j+5] = Ui1 + Vi1
		coeffs[j+6] = Ui2 + Vi2
		coeffs[j+7] = Ui3 + Vi3

		coeffs[j+N/2+0] = Ur0 - Vr0
		coeffs[j+N/2+1] = Ur1 - Vr1
		coeffs[j+N/2+2] = Ur2 - Vr2
		coeffs[j+N/2+3] = Ur3 - Vr3

		coeffs[j+N/2+4] = Ui0 - Vi0
		coeffs[j+N/2+5] = Ui1 - Vi1
		coeffs[j+N/2+6] = Ui2 - Vi2
		coeffs[j+N/2+7] = Ui3 - Vi3
	}
}

// untwistInPlace untwists the coefficients after inverse FFT.
// Equivalent to round(coeffs * w2NjInv).
func untwistInPlace(coeffs, w2NjInv []float64) {
	for i := 0; i < len(coeffs); i += 8 {
		c0 := math.Round(coeffs[i+0]*w2NjInv[i+0] - coeffs[i+4]*w2NjInv[i+4])
		c1 := math.Round(coeffs[i+1]*w2NjInv[i+1] - coeffs[i+5]*w2NjInv[i+5])
		c2 := math.Round(coeffs[i+2]*w2NjInv[i+2] - coeffs[i+6]*w2NjInv[i+6])
		c3 := math.Round(coeffs[i+3]*w2NjInv[i+3] - coeffs[i+7]*w2NjInv[i+7])

		c4 := math.Round(coeffs[i+0]*w2NjInv[i+4] + coeffs[i+4]*w2NjInv[i+0])
		c5 := math.Round(coeffs[i+1]*w2NjInv[i+5] + coeffs[i+5]*w2NjInv[i+1])
		c6 := math.Round(coeffs[i+2]*w2NjInv[i+6] + coeffs[i+6]*w2NjInv[i+2])
		c7 := math.Round(coeffs[i+3]*w2NjInv[i+7] + coeffs[i+7]*w2NjInv[i+3])

		coeffs[i+0] = c0
		coeffs[i+1] = c1
		coeffs[i+2] = c2
		coeffs[i+3] = c3

		coeffs[i+4] = c4
		coeffs[i+5] = c5
		coeffs[i+6] = c6
		coeffs[i+7] = c7
	}
}

// untwistAndScaleInPlace untwists the coefficients and scales it with maxT.
func untwistAndScaleInPlace(coeffs, w2NjInv []float64, maxT float64) {
	for i := 0; i < len(coeffs); i += 8 {
		c0 := coeffs[i+0]*w2NjInv[i+0] - coeffs[i+4]*w2NjInv[i+4]
		c1 := coeffs[i+1]*w2NjInv[i+1] - coeffs[i+5]*w2NjInv[i+5]
		c2 := coeffs[i+2]*w2NjInv[i+2] - coeffs[i+6]*w2NjInv[i+6]
		c3 := coeffs[i+3]*w2NjInv[i+3] - coeffs[i+7]*w2NjInv[i+7]

		c4 := coeffs[i+0]*w2NjInv[i+4] + coeffs[i+4]*w2NjInv[i+0]
		c5 := coeffs[i+1]*w2NjInv[i+5] + coeffs[i+5]*w2NjInv[i+1]
		c6 := coeffs[i+2]*w2NjInv[i+6] + coeffs[i+6]*w2NjInv[i+2]
		c7 := coeffs[i+3]*w2NjInv[i+7] + coeffs[i+7]*w2NjInv[i+3]

		coeffs[i+0] = (c0 - math.Round(c0)) * maxT
		coeffs[i+1] = (c1 - math.Round(c1)) * maxT
		coeffs[i+2] = (c2 - math.Round(c2)) * maxT
		coeffs[i+3] = (c3 - math.Round(c3)) * maxT

		coeffs[i+4] = (c4 - math.Round(c4)) * maxT
		coeffs[i+5] = (c5 - math.Round(c5)) * maxT
		coeffs[i+6] = (c6 - math.Round(c6)) * maxT
		coeffs[i+7] = (c7 - math.Round(c7)) * maxT
	}
}
