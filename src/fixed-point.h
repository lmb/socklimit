#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>

#include "common.h"

#define FRACTION_BITS (32)
#define INT_BITS (64 - FRACTION_BITS)

// An unsigned Q32.32 value, aka 32 bits for the integer and 32 bits for
// the fractional part.
typedef struct {
	__u64 v;
} q32;

_Static_assert(sizeof(q32) * 8 == INT_BITS + FRACTION_BITS, "q32 has wrong size");

static q32 FORCE_INLINE q32_int(__u32 integer)
{
	return (q32){(__u64)integer << FRACTION_BITS};
}

static bool FORCE_INLINE q32_gt(q32 a, q32 b)
{
	return a.v > b.v;
}

static __u32 FORCE_INLINE q32_trunc(q32 a)
{
	return (__u32)(a.v >> FRACTION_BITS);
}

static __u32 FORCE_INLINE q32_frac(q32 a)
{
	return (__u32)a.v;
}

static __u32 FORCE_INLINE q32_round(q32 a)
{
	__u32 integer = q32_trunc(a);

	if (q32_frac(a) >= 1 << (FRACTION_BITS - 1)) {
		integer++;
	}

	return integer;
}

static q32 FORCE_INLINE q32_sub(q32 a, q32 b)
{
	return (q32){a.v - b.v};
}

static q32 FORCE_INLINE q32_add(q32 a, q32 b)
{
	return (q32){a.v + b.v};
}

static q32 FORCE_INLINE q32_div_u32(q32 a, __u32 b)
{
	return (q32){a.v / (__u64)b};
}

static q32 q32_mul_frac(q32 a, __u32 frac)
{
	// Based on https://stackoverflow.com/a/28904636
	__u64 a_lo = (__u32)(__u64)a.v;
	__u64 a_hi = (__u32)((__u64)a.v >> 32);
	__u64 b_lo = frac;
	// b_hi is always zero.

	// a_x_b_hi is always zero.
	__u64 a_x_b_mid = a_hi * b_lo;
	// b_x_a_mid is always zero.
	__u64 a_x_b_lo = a_lo * b_lo;

	__u64 lo       = ((__u64)(__u32)a_x_b_mid << 32) + a_x_b_lo;
	__u64 hi_carry = ((__u64)(__u32)a_x_b_mid + (a_x_b_lo >> 32)) >> 32;
	__u64 hi       = (a_x_b_mid >> 32) + hi_carry;

	// Divide by the denominator by shifting out FRACTION_BITS out of the full
	// 128 bit value and taking the low N bits as the result.
	//     h h h h h h h h l l l l l l l l
	//           \_______________/
	//                result
	hi = (hi & ((1ull << INT_BITS) - 1)) << FRACTION_BITS;
	lo = lo >> INT_BITS;

	return (q32){hi | lo};
}
