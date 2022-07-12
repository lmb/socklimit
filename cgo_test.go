//go:build cgo && cgotest
// +build cgo,cgotest

package socklimit

import (
	"encoding/hex"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestFasthash64(t *testing.T) {
	golden := []struct {
		input []byte
		hash  uint64
	}{
		{[]byte("asdefg"), 0x07ffd15db88b150b},
		{[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."), 0xbb1655682c0ac75d},
	}

	for _, gold := range golden {
		have := fasthash64(gold.input)
		if have != gold.hash {
			t.Logf("\n%s", hex.Dump(gold.input))
			t.Errorf("Expected hash %016x, got %016x", gold.hash, have)
		}
	}
}

func TestEstimateRate(t *testing.T) {
	const E = 0.01

	for _, rate := range []uint32{
		1, 1000, 9999, cmMaxRate,
	} {
		interval := time.Second / time.Duration(rate)
		rate = uint32(time.Second / interval)

		t.Run(fmt.Sprint(rate), func(t *testing.T) {
			t.Log("rate", rate, "interval", interval)

			var oldTs uint64
			var oldRate uint32
			convergence := -1
			for i := 0; i < 1000; i++ {
				now := uint64(i) * uint64(interval)
				estimate := estimate_rate(oldRate, oldTs, now)
				if estimate > rate {
					t.Fatalf("Estimate exceeded %v on iteration %d: %v", rate, i, estimate)
				}
				if estimate < oldRate {
					t.Fatalf("Estimate doesn't increase monotonically")
				}
				t.Logf("estimate_rate(%v, %v, %v) = %v", oldRate, oldTs, now, estimate)
				oldRate, oldTs = estimate, now

				if convergence == -1 {
					if estimate >= uint32(float64(rate)*(1-E)) {
						convergence = i
					}
				} else if i == convergence+100 {
					break
				}
			}

			if convergence == -1 {
				t.Fatalf("Estimate %v did not reach %v", oldRate, rate)
			}

			t.Logf("Estimate converged to the target value after %d iterations", convergence+1)
		})
	}

}

func TestQ32(t *testing.T) {
	assertRounding := func(a q32, rounded uint32) {
		t.Helper()
		if r := q32_round(a); r != rounded {
			t.Errorf("round = %v not %v", r, rounded)
		}
	}
	assertValue := func(a q32, v float64) {
		t.Helper()
		i, f := math.Modf(v)

		if qi := q32_trunc(a); uint32(i) != qi {
			t.Errorf("trunc(%v) = %v not %v", a.Float(), qi, i)
		}

		ff := uint32(f * math.Pow(2, 32))
		qf := q32_frac(a)
		switch delta := int64(qf) - int64(ff); delta {
		case -1, 0, 1:
		default:
			t.Errorf("frac(%v) is %v not %v, delta %v", a.Float(), qf, ff, delta)
		}
	}

	pi := q32_value(3.14)
	assertValue(pi, 3.14)
	assertRounding(pi, 3)

	piHalf := q32_div_u32(pi, 2)
	assertValue(piHalf, 1.57)
	assertRounding(piHalf, 2)

	half := q32_value(0.5)
	assertRounding(half, 1)

	piHalf = q32_mul_frac(pi, q32_frac(half))
	assertValue(piHalf, 1.57)

	assertValue(q32_mul_frac(pi, 0), 0)
	assertValue(q32_mul_frac(pi, math.MaxUint32), 3.14*(1.0-math.Pow(2, -32)))
	assertValue(q32_mul_frac(q32_value(math.MaxUint32), q32_frac(half)), float64(math.MaxUint32)/2)
}
