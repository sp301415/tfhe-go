//go:build amd64 && !purego

package poly

import (
	"golang.org/x/sys/cpu"
)

func fftInPlaceAVX2(coeffs []float64, tw []complex128)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs []float64, tw []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		fftInPlaceAVX2(coeffs, tw)
		return
	}

	N := len(coeffs)
	w := 0

	// First Loop
	Wr := real(tw[w])
	Wi := imag(tw[w])
	w++
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

		coeffs[j+N/2+0] = Ur0 - Vr0W
		coeffs[j+N/2+1] = Ur1 - Vr1W
		coeffs[j+N/2+2] = Ur2 - Vr2W
		coeffs[j+N/2+3] = Ur3 - Vr3W

		coeffs[j+N/2+4] = Ui0 - Vi0W
		coeffs[j+N/2+5] = Ui1 - Vi1W
		coeffs[j+N/2+6] = Ui2 - Vi2W
		coeffs[j+N/2+7] = Ui3 - Vi3W
	}

	// Main Loop
	t := N / 2
	for m := 2; m < N/8; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := i * t << 1
			j2 := j1 + t

			Wr := real(tw[w])
			Wi := imag(tw[w])
			w++

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
	for j := 0; j < N; j += 8 {
		Wr := real(tw[w])
		Wi := imag(tw[w])
		w++

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
	for j := 0; j < N; j += 8 {
		Wr0 := real(tw[w])
		Wi0 := imag(tw[w])
		Wr1 := real(tw[w+1])
		Wi1 := imag(tw[w+1])
		w += 2

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

func invFFTInPlaceAVX2(coeffs []float64, twInv []complex128, NInv float64)

// invfftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func invFFTInPlace(coeffs []float64, twInv []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		invFFTInPlaceAVX2(coeffs, twInv, 2/float64(len(coeffs)))
		return
	}

	N := len(coeffs)
	w := 0

	// Stride 1
	for j := 0; j < N; j += 8 {
		Wr0 := real(twInv[w])
		Wi0 := imag(twInv[w])
		Wr1 := real(twInv[w+1])
		Wi1 := imag(twInv[w+1])
		w += 2

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
	for j := 0; j < N; j += 8 {
		Wr := real(twInv[w])
		Wi := imag(twInv[w])
		w++

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
	for m := N / 8; m > 2; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			j2 := j1 + t

			Wr := real(twInv[w])
			Wi := imag(twInv[w])
			w++

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
	}

	// Last Loop
	NInv := 2 / float64(N)
	Wr := real(twInv[w])
	Wi := imag(twInv[w])
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

		coeffs[j+0] = (Ur0 + Vr0) * NInv
		coeffs[j+1] = (Ur1 + Vr1) * NInv
		coeffs[j+2] = (Ur2 + Vr2) * NInv
		coeffs[j+3] = (Ur3 + Vr3) * NInv

		coeffs[j+4] = (Ui0 + Vi0) * NInv
		coeffs[j+5] = (Ui1 + Vi1) * NInv
		coeffs[j+6] = (Ui2 + Vi2) * NInv
		coeffs[j+7] = (Ui3 + Vi3) * NInv

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

		coeffs[j+N/2+0] = UVr0W
		coeffs[j+N/2+1] = UVr1W
		coeffs[j+N/2+2] = UVr2W
		coeffs[j+N/2+3] = UVr3W

		coeffs[j+N/2+4] = UVi0W
		coeffs[j+N/2+5] = UVi1W
		coeffs[j+N/2+6] = UVi2W
		coeffs[j+N/2+7] = UVi3W
	}
}
