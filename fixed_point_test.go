package socklimit

import (
	"math"
	"testing"
)

const fractionBits = 32

func floatToFixed(f float64) uint64 {
	ret := uint64(0)
	for i := 64 - fractionBits; i >= -fractionBits; i-- {
		ret = ret << 1
		if f >= math.Pow(2, float64(i)) {
			ret |= 1
			f -= math.Pow(2, float64(i))
		}
	}
	return ret
}

func fixedToFloat(f uint64) float64 {
	ret := float64(0)
	for i := 64 - fractionBits - 1; i >= -fractionBits; i-- {
		if f&(1<<(i+fractionBits)) != 0 {
			ret += math.Pow(2, float64(i))
		}
	}
	return ret
}

func TestFloatToFixedPoint(t *testing.T) {
	x := float64(1.0 / 7.0)
	y := fixedToFloat(floatToFixed(x))
	if math.Abs(y-x) > 0.000000001 {
		t.Fatal("Difference too large", x, y)
	}
}
