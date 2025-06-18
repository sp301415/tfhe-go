package main

import (
	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/reg"
)

func butterflyAVX2(uR, uI, vR, vI, wR, wI reg.VecVirtual) {
	vwR := YMM()
	VMULPD(wR, vR, vwR)
	VFNMADD231PD(wI, vI, vwR)

	vwI := YMM()
	VMULPD(wI, vR, vwI)
	VFMADD231PD(wR, vI, vwI)

	VSUBPD(vwR, uR, vR)
	VSUBPD(vwI, uI, vI)
	VADDPD(vwR, uR, uR)
	VADDPD(vwI, uI, uI)
}

func butterflyAVX2XMM(uR, uI, vR, vI, wR, wI reg.VecVirtual) {
	vwR := XMM()
	VMULPD(wR, vR, vwR)
	VFNMADD231PD(wI, vI, vwR)

	vwI := XMM()
	VMULPD(wI, vR, vwI)
	VFMADD231PD(wR, vI, vwI)

	VSUBPD(vwR, uR, vR)
	VSUBPD(vwI, uI, vI)
	VADDPD(vwR, uR, uR)
	VADDPD(vwI, uI, uI)
}

func invButterflyAVX2(uR, uI, vR, vI, wR, wI reg.VecVirtual) {
	vuR, vuI := YMM(), YMM()

	VSUBPD(vR, uR, vuR)
	VADDPD(vR, uR, uR)

	VSUBPD(vI, uI, vuI)
	VADDPD(vI, uI, uI)

	VMULPD(wR, vuR, vR)
	VFNMADD231PD(wI, vuI, vR)

	VMULPD(wI, vuR, vI)
	VFMADD231PD(wR, vuI, vI)
}

func invButterflyAVX2XMM(uR, uI, vR, vI, wR, wI reg.VecVirtual) {
	vuR, vuI := XMM(), XMM()

	VSUBPD(vR, uR, vuR)
	VADDPD(vR, uR, uR)

	VSUBPD(vI, uI, vuI)
	VADDPD(vI, uI, uI)

	VMULPD(wR, vuR, vR)
	VFNMADD231PD(wI, vuI, vR)

	VMULPD(wI, vuR, vI)
	VFMADD231PD(wR, vuI, vI)
}
