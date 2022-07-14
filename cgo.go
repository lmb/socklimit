//go:build cgo && cgotest
// +build cgo,cgotest

package socklimit

// #cgo CFLAGS: -Iinclude
// #include "stdlib.h"
// #include "fasthash.h"
// #include "src/ewma.h"
// #include "src/fixed-point.h"
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"math"
)

func fasthash64(buf []byte) uint64 {
	ptr := C.CBytes(buf)
	defer C.free(ptr)

	return uint64(C.fasthash64(ptr, C.__u64(len(buf)), 0))
}

func estimate_rate(old_rate uint32, old_ts, now uint64) uint32 {
	return uint32(C.estimate_rate(C.uint(old_rate), C.ulonglong(old_ts), C.ulonglong(now)))
}

type q32 C.q32

func (q q32) String() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(C.q32(q).v))
	return "0x" + hex.EncodeToString(b[:4]) + "_" + hex.EncodeToString(b[4:])
}

func (q q32) Float() float64 {
	return float64(q32_trunc(q)) + float64(q32_frac(q))*math.Pow(2, -32)
}

func q32_value(v float64) q32 {
	i, f := math.Modf(v)
	f = math.Round(math.Abs(f) * math.Pow(2, 32))
	return q32(C.q32{v: C.ulonglong(uint64(i)<<32 | uint64(uint32(float64(f))))})
}

func q32_trunc(a q32) uint32 {
	return uint32(C.q32_trunc(C.q32(a)))
}

func q32_round(a q32) uint32 {
	return uint32(C.q32_round(C.q32(a)))
}

func q32_frac(a q32) uint32 {
	return uint32(C.q32_frac(C.q32(a)))
}

func q32_div_u32(a q32, b uint32) q32 {
	return q32(C.q32_div_u32(C.q32(a), C.uint(b)))
}

func q32_mul_frac(a q32, frac uint32) q32 {
	return q32(C.q32_mul_frac(C.q32(a), C.uint(frac)))
}
