#pragma once

/*
 * Exponential weighted moving average
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static inline u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static inline u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq;

	new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

static inline u64 scale_up_fair(u64 value, u64 weight)
{
	return value * weight / 100;
}

static inline u64 scale_inverse_fair(u64 value, u64 weight)
{
	return value * 100 / weight;
}

extern volatile u64 slice_ns;
void stat_add(enum stat_idx idx, u64 addend);
