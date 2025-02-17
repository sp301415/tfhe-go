//go:build amd64 && !purego

package poly

import (
	"golang.org/x/sys/cpu"
)

// fftInPlace is a top-level function for FFT.
// All internal FFT implementations calls this function for performance.
func fftInPlace(coeffs []float64, tw []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		fftInPlaceAVX2(coeffs, tw)
		return
	}

	N := len(coeffs)
	w := 0

	wReal := real(tw[w])
	wImag := imag(tw[w])
	w++
	for j := 0; j < N/2; j += 8 {
		uReal0 := coeffs[j+0]
		uReal1 := coeffs[j+1]
		uReal2 := coeffs[j+2]
		uReal3 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		uImag1 := coeffs[j+5]
		uImag2 := coeffs[j+6]
		uImag3 := coeffs[j+7]

		vReal0 := coeffs[j+N/2+0]
		vReal1 := coeffs[j+N/2+1]
		vReal2 := coeffs[j+N/2+2]
		vReal3 := coeffs[j+N/2+3]

		vImag0 := coeffs[j+N/2+4]
		vImag1 := coeffs[j+N/2+5]
		vImag2 := coeffs[j+N/2+6]
		vImag3 := coeffs[j+N/2+7]

		vwReal0 := vReal0*wReal - vImag0*wImag
		vwReal1 := vReal1*wReal - vImag1*wImag
		vwReal2 := vReal2*wReal - vImag2*wImag
		vwReal3 := vReal3*wReal - vImag3*wImag

		vwImag0 := vReal0*wImag + vImag0*wReal
		vwImag1 := vReal1*wImag + vImag1*wReal
		vwImag2 := vReal2*wImag + vImag2*wReal
		vwImag3 := vReal3*wImag + vImag3*wReal

		uOutReal0 := uReal0 + vwReal0
		uOutReal1 := uReal1 + vwReal1
		uOutReal2 := uReal2 + vwReal2
		uOutReal3 := uReal3 + vwReal3

		uOutImag0 := uImag0 + vwImag0
		uOutImag1 := uImag1 + vwImag1
		uOutImag2 := uImag2 + vwImag2
		uOutImag3 := uImag3 + vwImag3

		vOutReal0 := uReal0 - vwReal0
		vOutReal1 := uReal1 - vwReal1
		vOutReal2 := uReal2 - vwReal2
		vOutReal3 := uReal3 - vwReal3

		vOutImag0 := uImag0 - vwImag0
		vOutImag1 := uImag1 - vwImag1
		vOutImag2 := uImag2 - vwImag2
		vOutImag3 := uImag3 - vwImag3

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = uOutReal1
		coeffs[j+2] = uOutReal2
		coeffs[j+3] = uOutReal3

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = uOutImag1
		coeffs[j+6] = uOutImag2
		coeffs[j+7] = uOutImag3

		coeffs[j+N/2+0] = vOutReal0
		coeffs[j+N/2+1] = vOutReal1
		coeffs[j+N/2+2] = vOutReal2
		coeffs[j+N/2+3] = vOutReal3

		coeffs[j+N/2+4] = vOutImag0
		coeffs[j+N/2+5] = vOutImag1
		coeffs[j+N/2+6] = vOutImag2
		coeffs[j+N/2+7] = vOutImag3

	}

	t := N / 2
	for m := 2; m <= N/16; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t

			wReal := real(tw[w])
			wImag := imag(tw[w])
			w++

			for j := j1; j < j2; j += 8 {
				uReal0 := coeffs[j+0]
				uReal1 := coeffs[j+1]
				uReal2 := coeffs[j+2]
				uReal3 := coeffs[j+3]

				uImag0 := coeffs[j+4]
				uImag1 := coeffs[j+5]
				uImag2 := coeffs[j+6]
				uImag3 := coeffs[j+7]

				vReal0 := coeffs[j+t+0]
				vReal1 := coeffs[j+t+1]
				vReal2 := coeffs[j+t+2]
				vReal3 := coeffs[j+t+3]

				vImag0 := coeffs[j+t+4]
				vImag1 := coeffs[j+t+5]
				vImag2 := coeffs[j+t+6]
				vImag3 := coeffs[j+t+7]

				vwReal0 := vReal0*wReal - vImag0*wImag
				vwReal1 := vReal1*wReal - vImag1*wImag
				vwReal2 := vReal2*wReal - vImag2*wImag
				vwReal3 := vReal3*wReal - vImag3*wImag

				vwImag0 := vReal0*wImag + vImag0*wReal
				vwImag1 := vReal1*wImag + vImag1*wReal
				vwImag2 := vReal2*wImag + vImag2*wReal
				vwImag3 := vReal3*wImag + vImag3*wReal

				uOutReal0 := uReal0 + vwReal0
				uOutReal1 := uReal1 + vwReal1
				uOutReal2 := uReal2 + vwReal2
				uOutReal3 := uReal3 + vwReal3

				uOutImag0 := uImag0 + vwImag0
				uOutImag1 := uImag1 + vwImag1
				uOutImag2 := uImag2 + vwImag2
				uOutImag3 := uImag3 + vwImag3

				vOutReal0 := uReal0 - vwReal0
				vOutReal1 := uReal1 - vwReal1
				vOutReal2 := uReal2 - vwReal2
				vOutReal3 := uReal3 - vwReal3

				vOutImag0 := uImag0 - vwImag0
				vOutImag1 := uImag1 - vwImag1
				vOutImag2 := uImag2 - vwImag2
				vOutImag3 := uImag3 - vwImag3

				coeffs[j+0] = uOutReal0
				coeffs[j+1] = uOutReal1
				coeffs[j+2] = uOutReal2
				coeffs[j+3] = uOutReal3

				coeffs[j+4] = uOutImag0
				coeffs[j+5] = uOutImag1
				coeffs[j+6] = uOutImag2
				coeffs[j+7] = uOutImag3

				coeffs[j+t+0] = vOutReal0
				coeffs[j+t+1] = vOutReal1
				coeffs[j+t+2] = vOutReal2
				coeffs[j+t+3] = vOutReal3

				coeffs[j+t+4] = vOutImag0
				coeffs[j+t+5] = vOutImag1
				coeffs[j+t+6] = vOutImag2
				coeffs[j+t+7] = vOutImag3
			}
		}
	}

	for j := 0; j < N; j += 8 {
		wReal := real(tw[w])
		wImag := imag(tw[w])
		w++

		uReal0 := coeffs[j+0]
		uReal1 := coeffs[j+1]

		vReal0 := coeffs[j+2]
		vReal1 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		uImag1 := coeffs[j+5]

		vImag0 := coeffs[j+6]
		vImag1 := coeffs[j+7]

		vwReal0 := vReal0*wReal - vImag0*wImag
		vwReal1 := vReal1*wReal - vImag1*wImag

		vwImag0 := vReal0*wImag + vImag0*wReal
		vwImag1 := vReal1*wImag + vImag1*wReal

		uOutReal0 := uReal0 + vwReal0
		uOutReal1 := uReal1 + vwReal1

		vOutReal0 := uReal0 - vwReal0
		vOutReal1 := uReal1 - vwReal1

		uOutImag0 := uImag0 + vwImag0
		uOutImag1 := uImag1 + vwImag1

		vOutImag0 := uImag0 - vwImag0
		vOutImag1 := uImag1 - vwImag1

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = uOutReal1

		coeffs[j+2] = vOutReal0
		coeffs[j+3] = vOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = uOutImag1

		coeffs[j+6] = vOutImag0
		coeffs[j+7] = vOutImag1
	}

	for j := 0; j < N; j += 8 {
		wReal0 := real(tw[w])
		wImag0 := imag(tw[w])
		wReal1 := real(tw[w+1])
		wImag1 := imag(tw[w+1])
		w += 2

		uReal0 := coeffs[j+0]
		vReal0 := coeffs[j+1]

		uReal1 := coeffs[j+2]
		vReal1 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		vImag0 := coeffs[j+5]

		uImag1 := coeffs[j+6]
		vImag1 := coeffs[j+7]

		vwReal0 := vReal0*wReal0 - vImag0*wImag0
		vwImag0 := vReal0*wImag0 + vImag0*wReal0

		vwReal1 := vReal1*wReal1 - vImag1*wImag1
		vwImag1 := vReal1*wImag1 + vImag1*wReal1

		uOutReal0 := uReal0 + vwReal0
		vOutReal0 := uReal0 - vwReal0

		uOutReal1 := uReal1 + vwReal1
		vOutReal1 := uReal1 - vwReal1

		uOutImag0 := uImag0 + vwImag0
		vOutImag0 := uImag0 - vwImag0

		uOutImag1 := uImag1 + vwImag1
		vOutImag1 := uImag1 - vwImag1

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = vOutReal0

		coeffs[j+2] = uOutReal1
		coeffs[j+3] = vOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = vOutImag0

		coeffs[j+6] = uOutImag1
		coeffs[j+7] = vOutImag1
	}
}

// ifftInPlace is a top-level function for inverse FFT.
// All internal inverse FFT implementations calls this function for performance.
func ifftInPlace(coeffs []float64, twInv []complex128) {
	if cpu.X86.HasAVX2 && cpu.X86.HasFMA {
		ifftInPlaceAVX2(coeffs, twInv, 2/float64(len(coeffs)))
		return
	}

	N := len(coeffs)
	w := 0

	for j := 0; j < N; j += 8 {
		wReal0 := real(twInv[w])
		wImag0 := imag(twInv[w])
		wReal1 := real(twInv[w+1])
		wImag1 := imag(twInv[w+1])
		w += 2

		uReal0 := coeffs[j+0]
		vReal0 := coeffs[j+1]

		uReal1 := coeffs[j+2]
		vReal1 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		vImag0 := coeffs[j+5]

		uImag1 := coeffs[j+6]
		vImag1 := coeffs[j+7]

		uOutReal0 := uReal0 + vReal0
		uOutReal1 := uReal1 + vReal1

		uOutImag0 := uImag0 + vImag0
		uOutImag1 := uImag1 + vImag1

		vOutReal0 := uReal0 - vReal0
		vOutReal1 := uReal1 - vReal1

		vOutImag0 := uImag0 - vImag0
		vOutImag1 := uImag1 - vImag1

		vwOutReal0 := vOutReal0*wReal0 - vOutImag0*wImag0
		vwOutReal1 := vOutReal1*wReal1 - vOutImag1*wImag1

		vwOutImag0 := vOutReal0*wImag0 + vOutImag0*wReal0
		vwOutImag1 := vOutReal1*wImag1 + vOutImag1*wReal1

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = vwOutReal0

		coeffs[j+2] = uOutReal1
		coeffs[j+3] = vwOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = vwOutImag0

		coeffs[j+6] = uOutImag1
		coeffs[j+7] = vwOutImag1
	}

	for j := 0; j < N; j += 8 {
		wReal := real(twInv[w])
		wImag := imag(twInv[w])
		w++

		uReal0 := coeffs[j+0]
		uReal1 := coeffs[j+1]

		vReal0 := coeffs[j+2]
		vReal1 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		uImag1 := coeffs[j+5]

		vImag0 := coeffs[j+6]
		vImag1 := coeffs[j+7]

		uOutReal0 := uReal0 + vReal0
		uOutReal1 := uReal1 + vReal1

		uOutImag0 := uImag0 + vImag0
		uOutImag1 := uImag1 + vImag1

		vOutReal0 := uReal0 - vReal0
		vOutReal1 := uReal1 - vReal1

		vOutImag0 := uImag0 - vImag0
		vOutImag1 := uImag1 - vImag1

		vwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
		vwOutReal1 := vOutReal1*wReal - vOutImag1*wImag

		vwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
		vwOutImag1 := vOutReal1*wImag + vOutImag1*wReal

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = uOutReal1

		coeffs[j+2] = vwOutReal0
		coeffs[j+3] = vwOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = uOutImag1

		coeffs[j+6] = vwOutImag0
		coeffs[j+7] = vwOutImag1
	}

	t := 8
	for m := N / 16; m >= 2; m >>= 1 {
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t

			wReal := real(twInv[w])
			wImag := imag(twInv[w])
			w++

			for j := j1; j < j2; j += 8 {
				uReal0 := coeffs[j+0]
				uReal1 := coeffs[j+1]
				uReal2 := coeffs[j+2]
				uReal3 := coeffs[j+3]

				uImag0 := coeffs[j+4]
				uImag1 := coeffs[j+5]
				uImag2 := coeffs[j+6]
				uImag3 := coeffs[j+7]

				vReal0 := coeffs[j+t+0]
				vReal1 := coeffs[j+t+1]
				vReal2 := coeffs[j+t+2]
				vReal3 := coeffs[j+t+3]

				vImag0 := coeffs[j+t+4]
				vImag1 := coeffs[j+t+5]
				vImag2 := coeffs[j+t+6]
				vImag3 := coeffs[j+t+7]

				uOutReal0 := uReal0 + vReal0
				uOutReal1 := uReal1 + vReal1
				uOutReal2 := uReal2 + vReal2
				uOutReal3 := uReal3 + vReal3

				uOutImag0 := uImag0 + vImag0
				uOutImag1 := uImag1 + vImag1
				uOutImag2 := uImag2 + vImag2
				uOutImag3 := uImag3 + vImag3

				vOutReal0 := uReal0 - vReal0
				vOutReal1 := uReal1 - vReal1
				vOutReal2 := uReal2 - vReal2
				vOutReal3 := uReal3 - vReal3

				vOutImag0 := uImag0 - vImag0
				vOutImag1 := uImag1 - vImag1
				vOutImag2 := uImag2 - vImag2
				vOutImag3 := uImag3 - vImag3

				vwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
				vwOutReal1 := vOutReal1*wReal - vOutImag1*wImag
				vwOutReal2 := vOutReal2*wReal - vOutImag2*wImag
				vwOutReal3 := vOutReal3*wReal - vOutImag3*wImag

				vwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
				vwOutImag1 := vOutReal1*wImag + vOutImag1*wReal
				vwOutImag2 := vOutReal2*wImag + vOutImag2*wReal
				vwOutImag3 := vOutReal3*wImag + vOutImag3*wReal

				coeffs[j+0] = uOutReal0
				coeffs[j+1] = uOutReal1
				coeffs[j+2] = uOutReal2
				coeffs[j+3] = uOutReal3

				coeffs[j+4] = uOutImag0
				coeffs[j+5] = uOutImag1
				coeffs[j+6] = uOutImag2
				coeffs[j+7] = uOutImag3

				coeffs[j+t+0] = vwOutReal0
				coeffs[j+t+1] = vwOutReal1
				coeffs[j+t+2] = vwOutReal2
				coeffs[j+t+3] = vwOutReal3

				coeffs[j+t+4] = vwOutImag0
				coeffs[j+t+5] = vwOutImag1
				coeffs[j+t+6] = vwOutImag2
				coeffs[j+t+7] = vwOutImag3
			}
		}
		t <<= 1
	}

	// Last Loop
	scale := float64(N / 2)
	wReal := real(twInv[w])
	wImag := imag(twInv[w])
	for j := 0; j < N/2; j += 8 {
		uReal0 := coeffs[j+0]
		uReal1 := coeffs[j+1]
		uReal2 := coeffs[j+2]
		uReal3 := coeffs[j+3]

		uImag0 := coeffs[j+4]
		uImag1 := coeffs[j+5]
		uImag2 := coeffs[j+6]
		uImag3 := coeffs[j+7]

		vReal0 := coeffs[j+N/2+0]
		vReal1 := coeffs[j+N/2+1]
		vReal2 := coeffs[j+N/2+2]
		vReal3 := coeffs[j+N/2+3]

		vImag0 := coeffs[j+N/2+4]
		vImag1 := coeffs[j+N/2+5]
		vImag2 := coeffs[j+N/2+6]
		vImag3 := coeffs[j+N/2+7]

		uOutReal0 := uReal0 + vReal0
		uOutReal1 := uReal1 + vReal1
		uOutReal2 := uReal2 + vReal2
		uOutReal3 := uReal3 + vReal3

		uOutImag0 := uImag0 + vImag0
		uOutImag1 := uImag1 + vImag1
		uOutImag2 := uImag2 + vImag2
		uOutImag3 := uImag3 + vImag3

		vOutReal0 := uReal0 - vReal0
		vOutReal1 := uReal1 - vReal1
		vOutReal2 := uReal2 - vReal2
		vOutReal3 := uReal3 - vReal3

		vOutImag0 := uImag0 - vImag0
		vOutImag1 := uImag1 - vImag1
		vOutImag2 := uImag2 - vImag2
		vOutImag3 := uImag3 - vImag3

		vwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
		vwOutReal1 := vOutReal1*wReal - vOutImag1*wImag
		vwOutReal2 := vOutReal2*wReal - vOutImag2*wImag
		vwOutReal3 := vOutReal3*wReal - vOutImag3*wImag

		vwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
		vwOutImag1 := vOutReal1*wImag + vOutImag1*wReal
		vwOutImag2 := vOutReal2*wImag + vOutImag2*wReal
		vwOutImag3 := vOutReal3*wImag + vOutImag3*wReal

		coeffs[j+0] = uOutReal0 / scale
		coeffs[j+1] = uOutReal1 / scale
		coeffs[j+2] = uOutReal2 / scale
		coeffs[j+3] = uOutReal3 / scale

		coeffs[j+4] = uOutImag0 / scale
		coeffs[j+5] = uOutImag1 / scale
		coeffs[j+6] = uOutImag2 / scale
		coeffs[j+7] = uOutImag3 / scale

		coeffs[j+N/2+0] = vwOutReal0 / scale
		coeffs[j+N/2+1] = vwOutReal1 / scale
		coeffs[j+N/2+2] = vwOutReal2 / scale
		coeffs[j+N/2+3] = vwOutReal3 / scale

		coeffs[j+N/2+4] = vwOutImag0 / scale
		coeffs[j+N/2+5] = vwOutImag1 / scale
		coeffs[j+N/2+6] = vwOutImag2 / scale
		coeffs[j+N/2+7] = vwOutImag3 / scale
	}
}
