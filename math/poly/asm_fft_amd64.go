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

		vTwReal0 := vReal0*wReal - vImag0*wImag
		vTwReal1 := vReal1*wReal - vImag1*wImag
		vTwReal2 := vReal2*wReal - vImag2*wImag
		vTwReal3 := vReal3*wReal - vImag3*wImag

		vTwImag0 := vReal0*wImag + vImag0*wReal
		vTwImag1 := vReal1*wImag + vImag1*wReal
		vTwImag2 := vReal2*wImag + vImag2*wReal
		vTwImag3 := vReal3*wImag + vImag3*wReal

		uOutReal0 := uReal0 + vTwReal0
		uOutReal1 := uReal1 + vTwReal1
		uOutReal2 := uReal2 + vTwReal2
		uOutReal3 := uReal3 + vTwReal3

		uOutImag0 := uImag0 + vTwImag0
		uOutImag1 := uImag1 + vTwImag1
		uOutImag2 := uImag2 + vTwImag2
		uOutImag3 := uImag3 + vTwImag3

		vOutReal0 := uReal0 - vTwReal0
		vOutReal1 := uReal1 - vTwReal1
		vOutReal2 := uReal2 - vTwReal2
		vOutReal3 := uReal3 - vTwReal3

		vOutImag0 := uImag0 - vTwImag0
		vOutImag1 := uImag1 - vTwImag1
		vOutImag2 := uImag2 - vTwImag2
		vOutImag3 := uImag3 - vTwImag3

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

				vTwReal0 := vReal0*wReal - vImag0*wImag
				vTwReal1 := vReal1*wReal - vImag1*wImag
				vTwReal2 := vReal2*wReal - vImag2*wImag
				vTwReal3 := vReal3*wReal - vImag3*wImag

				vTwImag0 := vReal0*wImag + vImag0*wReal
				vTwImag1 := vReal1*wImag + vImag1*wReal
				vTwImag2 := vReal2*wImag + vImag2*wReal
				vTwImag3 := vReal3*wImag + vImag3*wReal

				uOutReal0 := uReal0 + vTwReal0
				uOutReal1 := uReal1 + vTwReal1
				uOutReal2 := uReal2 + vTwReal2
				uOutReal3 := uReal3 + vTwReal3

				uOutImag0 := uImag0 + vTwImag0
				uOutImag1 := uImag1 + vTwImag1
				uOutImag2 := uImag2 + vTwImag2
				uOutImag3 := uImag3 + vTwImag3

				vOutReal0 := uReal0 - vTwReal0
				vOutReal1 := uReal1 - vTwReal1
				vOutReal2 := uReal2 - vTwReal2
				vOutReal3 := uReal3 - vTwReal3

				vOutImag0 := uImag0 - vTwImag0
				vOutImag1 := uImag1 - vTwImag1
				vOutImag2 := uImag2 - vTwImag2
				vOutImag3 := uImag3 - vTwImag3

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

		vTwReal0 := vReal0*wReal - vImag0*wImag
		vTwReal1 := vReal1*wReal - vImag1*wImag

		vTwImag0 := vReal0*wImag + vImag0*wReal
		vTwImag1 := vReal1*wImag + vImag1*wReal

		uOutReal0 := uReal0 + vTwReal0
		uOutReal1 := uReal1 + vTwReal1

		vOutReal0 := uReal0 - vTwReal0
		vOutReal1 := uReal1 - vTwReal1

		uOutImag0 := uImag0 + vTwImag0
		uOutImag1 := uImag1 + vTwImag1

		vOutImag0 := uImag0 - vTwImag0
		vOutImag1 := uImag1 - vTwImag1

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

		vTwReal0 := vReal0*wReal0 - vImag0*wImag0
		vTwImag0 := vReal0*wImag0 + vImag0*wReal0

		vTwReal1 := vReal1*wReal1 - vImag1*wImag1
		vTwImag1 := vReal1*wImag1 + vImag1*wReal1

		uOutReal0 := uReal0 + vTwReal0
		vOutReal0 := uReal0 - vTwReal0

		uOutReal1 := uReal1 + vTwReal1
		vOutReal1 := uReal1 - vTwReal1

		uOutImag0 := uImag0 + vTwImag0
		vOutImag0 := uImag0 - vTwImag0

		uOutImag1 := uImag1 + vTwImag1
		vOutImag1 := uImag1 - vTwImag1

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

		vTwOutReal0 := vOutReal0*wReal0 - vOutImag0*wImag0
		vTwOutReal1 := vOutReal1*wReal1 - vOutImag1*wImag1

		vTwOutImag0 := vOutReal0*wImag0 + vOutImag0*wReal0
		vTwOutImag1 := vOutReal1*wImag1 + vOutImag1*wReal1

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = vTwOutReal0

		coeffs[j+2] = uOutReal1
		coeffs[j+3] = vTwOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = vTwOutImag0

		coeffs[j+6] = uOutImag1
		coeffs[j+7] = vTwOutImag1
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

		vTwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
		vTwOutReal1 := vOutReal1*wReal - vOutImag1*wImag

		vTwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
		vTwOutImag1 := vOutReal1*wImag + vOutImag1*wReal

		coeffs[j+0] = uOutReal0
		coeffs[j+1] = uOutReal1

		coeffs[j+2] = vTwOutReal0
		coeffs[j+3] = vTwOutReal1

		coeffs[j+4] = uOutImag0
		coeffs[j+5] = uOutImag1

		coeffs[j+6] = vTwOutImag0
		coeffs[j+7] = vTwOutImag1
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

				vTwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
				vTwOutReal1 := vOutReal1*wReal - vOutImag1*wImag
				vTwOutReal2 := vOutReal2*wReal - vOutImag2*wImag
				vTwOutReal3 := vOutReal3*wReal - vOutImag3*wImag

				vTwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
				vTwOutImag1 := vOutReal1*wImag + vOutImag1*wReal
				vTwOutImag2 := vOutReal2*wImag + vOutImag2*wReal
				vTwOutImag3 := vOutReal3*wImag + vOutImag3*wReal

				coeffs[j+0] = uOutReal0
				coeffs[j+1] = uOutReal1
				coeffs[j+2] = uOutReal2
				coeffs[j+3] = uOutReal3

				coeffs[j+4] = uOutImag0
				coeffs[j+5] = uOutImag1
				coeffs[j+6] = uOutImag2
				coeffs[j+7] = uOutImag3

				coeffs[j+t+0] = vTwOutReal0
				coeffs[j+t+1] = vTwOutReal1
				coeffs[j+t+2] = vTwOutReal2
				coeffs[j+t+3] = vTwOutReal3

				coeffs[j+t+4] = vTwOutImag0
				coeffs[j+t+5] = vTwOutImag1
				coeffs[j+t+6] = vTwOutImag2
				coeffs[j+t+7] = vTwOutImag3
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

		vTwOutReal0 := vOutReal0*wReal - vOutImag0*wImag
		vTwOutReal1 := vOutReal1*wReal - vOutImag1*wImag
		vTwOutReal2 := vOutReal2*wReal - vOutImag2*wImag
		vTwOutReal3 := vOutReal3*wReal - vOutImag3*wImag

		vTwOutImag0 := vOutReal0*wImag + vOutImag0*wReal
		vTwOutImag1 := vOutReal1*wImag + vOutImag1*wReal
		vTwOutImag2 := vOutReal2*wImag + vOutImag2*wReal
		vTwOutImag3 := vOutReal3*wImag + vOutImag3*wReal

		coeffs[j+0] = uOutReal0 / scale
		coeffs[j+1] = uOutReal1 / scale
		coeffs[j+2] = uOutReal2 / scale
		coeffs[j+3] = uOutReal3 / scale

		coeffs[j+4] = uOutImag0 / scale
		coeffs[j+5] = uOutImag1 / scale
		coeffs[j+6] = uOutImag2 / scale
		coeffs[j+7] = uOutImag3 / scale

		coeffs[j+N/2+0] = vTwOutReal0 / scale
		coeffs[j+N/2+1] = vTwOutReal1 / scale
		coeffs[j+N/2+2] = vTwOutReal2 / scale
		coeffs[j+N/2+3] = vTwOutReal3 / scale

		coeffs[j+N/2+4] = vTwOutImag0 / scale
		coeffs[j+N/2+5] = vTwOutImag1 / scale
		coeffs[j+N/2+6] = vTwOutImag2 / scale
		coeffs[j+N/2+7] = vTwOutImag3 / scale
	}
}
