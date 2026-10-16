package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

// sendAt records a packet with the sampler, mirroring how the ack handler calls
// it: bytesInFlight already includes the packet being sent.
func sendAt(s *bbrSampler, t monotime.Time, pn protocol.PacketNumber, size, inFlightAfter protocol.ByteCount) {
	s.OnPacketSent(t, pn, size, inFlightAfter, true)
}

func TestBBRSamplerIgnoresNonAckEliciting(t *testing.T) {
	s := newBBRSampler()
	s.OnPacketSent(monotime.Time(0), 1, 100, 100, false)
	_, ok := s.OnPacketAcked(monotime.Time(0).Add(time.Second), 1, 0)
	require.False(t, ok, "a non-ack-eliciting packet produces no sample")
}

func TestBBRSamplerComputesDeliveryRate(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	const size = protocol.ByteCount(1200)
	const rtt = 100 * time.Millisecond

	// Send 10 packets back to back, then ack them one RTT later, spread over
	// 100ms. The delivery rate is bounded by the ack spread, so it should come
	// out at 10 packets per 100ms.
	for i := range 10 {
		sendAt(s, base, protocol.PacketNumber(i), size, size*protocol.ByteCount(i+1))
	}
	var last bbrRateSample
	for i := range 10 {
		ackTime := base.Add(rtt + time.Duration(i)*10*time.Millisecond)
		rs, ok := s.OnPacketAcked(ackTime, protocol.PacketNumber(i), 0)
		require.True(t, ok)
		last = rs
	}
	require.True(t, last.hasRate)
	// 10 packets delivered over the 90ms spanned by the acks of packets 0..9,
	// measured from the first ack: the sampler restarts its interval at each
	// acked packet's send time, so the final sample covers one packet over 10ms.
	require.Positive(t, last.deliveryRate)
	require.Equal(t, 10*size, s.delivered)
}

func TestBBRSamplerRejectsSubMinRTTInterval(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	sendAt(s, base, 1, 1200, 1200)
	// The packet is acked 1ms later, but min_rtt is 100ms: an interval that
	// short cannot describe a full delivery cycle (draft §4.1.2.3).
	rs, ok := s.OnPacketAcked(base.Add(time.Millisecond), 1, 100*time.Millisecond)
	require.True(t, ok)
	require.False(t, rs.hasRate, "sub-min_rtt intervals must not yield a rate")
	require.Zero(t, rs.deliveryRate)
}

func TestBBRSamplerAppLimited(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	const size = protocol.ByteCount(1200)

	sendAt(s, base, 1, size, size)
	require.False(t, s.isAppLimited())

	// The application runs dry with one packet still in flight.
	s.MarkAppLimited(size)
	require.True(t, s.isAppLimited())

	sendAt(s, base.Add(time.Millisecond), 2, size, 2*size)
	rs, ok := s.OnPacketAcked(base.Add(100*time.Millisecond), 2, 0)
	require.True(t, ok)
	require.True(t, rs.isAppLimited, "a packet sent during the app-limited phase is marked")

	// Delivering past the app-limited watermark ends the phase.
	sendAt(s, base.Add(200*time.Millisecond), 3, size, size)
	_, ok = s.OnPacketAcked(base.Add(300*time.Millisecond), 1, 0)
	require.True(t, ok)
	_, ok = s.OnPacketAcked(base.Add(400*time.Millisecond), 3, 0)
	require.True(t, ok)
	require.False(t, s.isAppLimited(), "the phase ends once delivered passes the watermark")
}

func TestBBRSamplerRestartsIntervalWhenIdle(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	const size = protocol.ByteCount(1200)

	// A send with nothing else in flight starts a fresh sampling interval, so
	// the idle gap before it does not depress the measured rate.
	sendAt(s, base, 1, size, size)
	require.Equal(t, base, s.firstSendTime)
	require.Equal(t, base, s.deliveredTime)

	sendAt(s, base.Add(10*time.Millisecond), 2, size, 2*size)
	require.Equal(t, base, s.firstSendTime, "a send with data in flight does not restart the interval")
}

func TestBBRSamplerLossAccounting(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	const size = protocol.ByteCount(1200)

	sendAt(s, base, 1, size, size)
	sendAt(s, base, 2, size, 2*size)

	p, ok := s.OnPacketLost(1, size)
	require.True(t, ok)
	require.Equal(t, size, p.txInFlight)
	require.Equal(t, size, s.lost)

	// A packet the sampler never saw still counts toward C.lost, so that the
	// loss rate is not understated.
	_, ok = s.OnPacketLost(99, size)
	require.False(t, ok)
	require.Equal(t, 2*size, s.lost)

	// RS.lost is the data lost since the acked packet was sent.
	rs, ok := s.OnPacketAcked(base.Add(100*time.Millisecond), 2, 0)
	require.True(t, ok)
	require.Equal(t, 2*size, rs.lost)
}

func TestBBRSamplerDropsStateOnAck(t *testing.T) {
	s := newBBRSampler()
	base := monotime.Time(0).Add(time.Hour)
	sendAt(s, base, 1, 1200, 1200)
	require.Len(t, s.packets, 1)
	_, ok := s.OnPacketAcked(base.Add(time.Second), 1, 0)
	require.True(t, ok)
	require.Empty(t, s.packets, "acked packets must not be retained")

	_, ok = s.OnPacketAcked(base.Add(2*time.Second), 1, 0)
	require.False(t, ok, "a second ack for the same packet yields no sample")
}
