package congestion

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowedMaxFilterEmpty(t *testing.T) {
	var f windowedMaxFilter
	require.Zero(t, f.Best())
}

func TestWindowedMaxFilterTracksMaximum(t *testing.T) {
	var f windowedMaxFilter
	f.Update(10, 0, 4)
	require.Equal(t, int64(10), f.Best())
	f.Update(5, 1, 4)
	require.Equal(t, int64(10), f.Best(), "a smaller sample must not lower the max")
	f.Update(20, 2, 4)
	require.Equal(t, int64(20), f.Best())
}

func TestWindowedMaxFilterExpiresStaleMaximum(t *testing.T) {
	var f windowedMaxFilter
	const window = 4
	f.Update(100, 0, window)
	// Feed smaller samples until the 100 falls out of the window.
	for now := int64(1); now <= 5; now++ {
		f.Update(10, now, window)
	}
	require.Equal(t, int64(10), f.Best(), "the maximum must expire once it leaves the window")
}

func TestWindowedMaxFilterPromotesSecondBest(t *testing.T) {
	var f windowedMaxFilter
	const window = 8
	f.Update(100, 0, window)
	f.Update(50, 4, window)
	// At time 9 the 100 (recorded at 0) is outside an 8-wide window, but the 50
	// recorded at 4 is still inside it and must take over.
	f.Update(10, 9, window)
	require.Equal(t, int64(50), f.Best())
}

func TestWindowedMaxFilterClear(t *testing.T) {
	var f windowedMaxFilter
	f.Update(42, 0, 4)
	require.Equal(t, int64(42), f.Best())
	f.Clear()
	require.Zero(t, f.Best())
	f.Update(7, 0, 4)
	require.Equal(t, int64(7), f.Best(), "the first sample after Clear must become the max")
}
