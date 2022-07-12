//go:build cgo && cgotest
// +build cgo,cgotest

package socklimit

// #cgo CFLAGS: -Iinclude
// #include "stdlib.h"
// #include "fasthash.h"
import "C"

func fasthash64(buf []byte) uint64 {
	ptr := C.CBytes(buf)
	defer C.free(ptr)

	return uint64(C.fasthash64(ptr, C.__u64(len(buf)), 0))
}
