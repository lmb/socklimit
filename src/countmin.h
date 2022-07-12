#pragma once
#include <linux/bpf.h>
#include <linux/types.h>
#include <mindef.h>

#include "common.h"
#include "ewma.h"
#include "fasthash.h"
#include "fixed-point.h"
#include "lookup3.h"

// countmin sketch paper: http://dimacs.rutgers.edu/~graham/pubs/papers/cm-full.pdf
//
// A cm sketch can be thought of as a two dimensional array width d rows and
// w columns. Each row uses a distinct hash function to index into its columns.
//
// The paper shows the following error bounds for the estimation, provided we
// choose d = ceil(ln(1/gamma)) and w = ceil(e/E) (see page 7).
//
//     a  <= a'
//     a' <= E * ||a||          with probability at least (1 - gamma)
//     a    : the true answer
//     a'   : the estimate made by the cm sketch
//     E    : a chosen error bound
//     gamma: desired probability of the upper bound
//     ||a||: the sum of all previous observations (I think)
//
// We always choose w to be a power of two to be able to cheaply index into the cm
// sketch based on a hash value. For d = 2 and w = 512 we get gamma ~0.14 and E ~0.005.
//
//     a <= a' <= ~0.005 * ||a|| (with probability ~0.86)
//
// Using 3 instead of 2 hash functions would increase the probability to 0.96. For
// that we need another function however.

#define HASHFN_N 2
#define COLUMNS 512

#define CM_RATE_BITS (24) // aka 16m pps
#define CM_TS_BITS (64 - CM_RATE_BITS)

#define CM_MAX_RATE ((1ull << CM_RATE_BITS) - 1)
#define CM_MAX_TS ((1ull << CM_TS_BITS) - 1)

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct cm_value {
	__u32 rate : CM_RATE_BITS;
	__u64 ts : CM_TS_BITS;
};

_Static_assert(sizeof(struct cm_value) == sizeof(__u64), "struct cm_value doesn't fit 64 bit word");

struct cm_hash {
	__u32 values[HASHFN_N];
};

struct countmin {
	struct cm_value values[HASHFN_N][COLUMNS];
};

// add element and determine count
static __u32 __attribute__ ((noinline)) cm_add_and_query(struct countmin *cm, __u64 now, const struct cm_hash *h)
{
	__u32 min = -1;

	now &= CM_MAX_TS;

#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(cm->values); i++) {
		__u32 target_idx      = h->values[i] & (ARRAY_SIZE(cm->values[i]) - 1);
		struct cm_value value = READ_ONCE(cm->values[i][target_idx]);
		__u32 rate            = estimate_rate(value.rate, value.ts, now);

		if (rate > CM_MAX_RATE) {
			rate = CM_MAX_RATE;
		}

		if (rate < min) {
			min = rate;
		}

		value.rate = rate;
		value.ts   = now;
		WRITE_ONCE(cm->values[i][target_idx], value);
	}
	return min;
}
