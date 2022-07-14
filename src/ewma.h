#pragma once

#include <linux/types.h>

#include "common.h"
#include "fixed-point.h"

// estimate_rate takes a previous rate and a duration that elapsed
// since this rate has been determined, and estimates based on these
// the current rate in packets per second.
static __u32 __attribute__ ((noinline)) estimate_rate(__u32 old_rate, __u64 old_ts, __u64 now)
{
	const q32 ONE_SECOND_NS = q32_int(1000000000u);

	// alpha is the smoothing factor. Assuming a constant inter-arrival time, you can
	// choose how many samples n are required for the estimate to be within error E
	// of the true rate:
	//    alpha = 1 - root(E, n)
	// Here alpha is encoded as a 32 bit fraction. Convert the alpha above like so
	//    alpha' = alpha / 20^-32
	// We've chosen it so that the estimate is accurate to 1. If
	//     delta * alpha < 0.5
	// we will round down to 0 and the estimate won't change. Thefore:
	//    alpha = (0.50 / 2^-32) + 1
	const __u32 alpha = 2147483649u;

	if (old_ts >= now) {
		// Time went backward due to clockskew or timer overflow. Return the old
		// value since we can't compute the current rate.
		return old_rate;
	}

	__u32 elapsed    = now - old_ts;
	q32 current_rate = q32_div_u32(ONE_SECOND_NS, elapsed);
	q32 estimate     = q32_int(old_rate);

	if (q32_gt(current_rate, estimate)) {
		q32 delta = q32_sub(current_rate, estimate);
		estimate  = q32_add(estimate, q32_mul_frac(delta, alpha));
	} else {
		q32 delta = q32_sub(estimate, current_rate);
		estimate  = q32_sub(estimate, q32_mul_frac(delta, alpha));
	}

	return q32_round(estimate);
}