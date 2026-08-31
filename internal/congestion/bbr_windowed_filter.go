package congestion

// windowedMaxFilter tracks the maximum of a stream of samples over a sliding
// window of "time", where time is an arbitrary monotonically increasing int64
// supplied by the caller (BBR uses packet-timed round trips and ProbeBW cycle
// counts, never the wall clock).
//
// It is Kathleen Nichols' algorithm, as referenced by
// draft-ietf-ccwg-bbr-06 §5.5.5 and implemented in Linux as lib/win_minmax.c.
// Three samples are enough to always have a valid maximum for the window: the
// best sample, the best of the most recent 3/4 of the window, and the best of
// the most recent 1/4. As the best sample ages out, the second takes over.
//
// The window length is passed per update rather than fixed at construction
// because BBR.extra_acked_filter uses a window of 1 round in Startup and 10
// rounds afterwards (§5.5.9).
type windowedMaxFilter struct {
	initialized bool
	estimates   [3]windowedSample
}

type windowedSample struct {
	value int64
	time  int64
}

// Update records a sample taken at time now, expiring samples older than
// windowLength.
func (f *windowedMaxFilter) Update(value, now, windowLength int64) {
	s := windowedSample{value: value, time: now}

	// A new maximum, an uninitialized filter, or a filter whose samples have
	// all aged out: this sample becomes the whole window.
	if !f.initialized || value >= f.estimates[0].value || now-f.estimates[2].time > windowLength {
		f.Reset(value, now)
		return
	}

	if value >= f.estimates[1].value {
		f.estimates[1] = s
		f.estimates[2] = s
	} else if value >= f.estimates[2].value {
		f.estimates[2] = s
	}

	// Expire the best estimate if it has aged out of the window, promoting the
	// runners-up. Two rounds of promotion can be needed if the second-best is
	// itself already out of the window.
	if now-f.estimates[0].time > windowLength {
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = s
		if now-f.estimates[0].time > windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
			f.estimates[2] = s
		}
		return
	}
	// Refresh the runners-up once they have gone stale, so that they are
	// representative of their sub-windows rather than of the best sample.
	if f.estimates[1].value == f.estimates[0].value && now-f.estimates[1].time > windowLength>>2 {
		f.estimates[1] = s
		f.estimates[2] = s
		return
	}
	if f.estimates[2].value == f.estimates[1].value && now-f.estimates[2].time > windowLength>>1 {
		f.estimates[2] = s
	}
}

// Best returns the maximum sample in the window, or 0 if no sample was ever
// recorded.
func (f *windowedMaxFilter) Best() int64 {
	if !f.initialized {
		return 0
	}
	return f.estimates[0].value
}

// Reset collapses the filter onto a single sample.
func (f *windowedMaxFilter) Reset(value, now int64) {
	s := windowedSample{value: value, time: now}
	f.estimates = [3]windowedSample{s, s, s}
	f.initialized = true
}

// Clear returns the filter to its zero state, discarding every sample.
func (f *windowedMaxFilter) Clear() {
	f.initialized = false
	f.estimates = [3]windowedSample{}
}
