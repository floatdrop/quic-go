package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter"
)

// ByteCount is a number of bytes.
type ByteCount = protocol.ByteCount

// PacketNumber is the number of a QUIC packet, as defined in RFC 9000, section 12.3.
type PacketNumber = protocol.PacketNumber

// Time is a monotonic timestamp. Congestion controllers receive event times in
// this form rather than as a time.Time: it is monotonic by construction, so it
// is unaffected by wall-clock adjustments, and cheaper to read.
type Time = monotime.Time

// An RTTStatsProvider gives a congestion controller read access to the
// connection's round-trip time estimates.
type RTTStatsProvider interface {
	// MinRTT is the minimum RTT observed over the lifetime of the connection.
	MinRTT() time.Duration
	// LatestRTT is the most recent RTT sample.
	LatestRTT() time.Duration
	// SmoothedRTT is the exponentially weighted moving average of RTT samples,
	// as defined in RFC 9002, section 5.3.
	SmoothedRTT() time.Duration
}

// A CongestionController decides when and how fast a connection may send.
//
// quic-go calls these methods from the connection's own goroutine, one at a
// time, so an implementation does not need to be safe for concurrent use. They
// are on the per-packet hot path: OnPacketSent and OnPacketAcked run for every
// packet the connection sends and every packet the peer acknowledges.
//
// Implementations are supplied through [Config.Congestion]. See [NewBBRv3],
// [NewReno], and [NewCubic] for the controllers quic-go ships with.
type CongestionController interface {
	// TimeUntilSend returns the time at which the next packet may be sent.
	// A zero value means a packet may be sent immediately.
	TimeUntilSend(bytesInFlight ByteCount) Time
	// HasPacingBudget says whether a packet may be sent at time now without
	// violating the pacing rate.
	HasPacingBudget(now Time) bool
	// OnPacketSent is called for every packet sent. bytesInFlight is the volume
	// in flight including this packet.
	OnPacketSent(sentTime Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount, isRetransmittable bool)
	// CanSend says whether the congestion window allows another packet.
	CanSend(bytesInFlight ByteCount) bool
	// MaybeExitSlowStart is a hint that slow start may be over. Controllers that
	// decide this for themselves may ignore it.
	MaybeExitSlowStart()
	// OnPacketAcked is called once for each newly acknowledged packet.
	// priorInFlight is the volume in flight before the ACK was processed.
	OnPacketAcked(number PacketNumber, ackedBytes ByteCount, priorInFlight ByteCount, eventTime Time)
	// OnCongestionEvent is called for each packet declared lost, and once per
	// ACK that reports ECN congestion (with lostBytes zero).
	OnCongestionEvent(number PacketNumber, lostBytes ByteCount, priorInFlight ByteCount)
	// OnRetransmissionTimeout is called when the probe timeout fires.
	OnRetransmissionTimeout(packetsRetransmitted bool)
	// SetMaxDatagramSize is called when Path MTU Discovery finds a larger
	// packet size. The size never decreases for a given path.
	SetMaxDatagramSize(ByteCount)

	// InSlowStart reports whether the controller is in its initial ramp-up.
	InSlowStart() bool
	// InRecovery reports whether the controller is responding to loss.
	InRecovery() bool
	// GetCongestionWindow returns the current congestion window.
	GetCongestionWindow() ByteCount
}

// CongestionController and the internal interface must stay method-for-method
// identical: that is what lets a controller supplied through Config.Congestion
// be used directly, with no adapter on the per-packet path.
var _ congestion.SendAlgorithmWithDebugInfos = CongestionController(nil)

// A CongestionControllerFactory builds the congestion controller for a
// connection. It is called when the connection is created, and again after each
// path migration, since the previous path's model no longer describes the new
// one.
type CongestionControllerFactory func(
	rttStats RTTStatsProvider,
	initialMaxDatagramSize ByteCount,
	qlogger qlogwriter.Recorder,
) CongestionController

// NewBBRv3 returns quic-go's BBRv3 controller, as specified in
// draft-ietf-ccwg-bbr-06. It is the default, and what a nil [Config.Congestion]
// selects.
//
// BBR paces at a gain-scaled multiple of the delivery rate it measures, and
// treats loss below its 2% threshold as noise rather than congestion. Relative
// to Reno it sustains far more throughput on paths with random loss or
// reordering, and holds a much shorter queue on paths with deep buffers, at the
// cost of a few percent of throughput on clean high-bandwidth-delay paths.
func NewBBRv3(rttStats RTTStatsProvider, initialMaxDatagramSize ByteCount, qlogger qlogwriter.Recorder) CongestionController {
	return congestion.NewBBRSender(congestion.DefaultClock{}, rttStats, initialMaxDatagramSize, qlogger)
}

// NewReno returns the NewReno controller of RFC 9002, which quic-go used as its
// default before BBRv3. It halves its congestion window on any loss, so on a
// path that drops or reorders packets for reasons other than congestion it will
// substantially underperform [NewBBRv3]. It is here so that a deployment can
// compare the two on real traffic, and as a fallback.
func NewReno(rttStats RTTStatsProvider, initialMaxDatagramSize ByteCount, qlogger qlogwriter.Recorder) CongestionController {
	return congestion.NewCubicSender(congestion.DefaultClock{}, rttStats, initialMaxDatagramSize, true, qlogger)
}

// NewCubic returns the CUBIC controller of RFC 9438. Like [NewReno] it is
// loss-based, but it recovers its window faster after a loss, which matters most
// on paths with a high bandwidth-delay product.
func NewCubic(rttStats RTTStatsProvider, initialMaxDatagramSize ByteCount, qlogger qlogwriter.Recorder) CongestionController {
	return congestion.NewCubicSender(congestion.DefaultClock{}, rttStats, initialMaxDatagramSize, false, qlogger)
}

// toAckhandlerFactory adapts a public factory to the one the ack handler wants.
// Only the factory signature is bridged; the controller it returns is passed
// through unchanged, so no wrapper sits on the per-packet path.
func toAckhandlerFactory(f CongestionControllerFactory) ackhandler.CongestionControllerFactory {
	if f == nil {
		return nil
	}
	return func(
		rttStats congestion.RTTStatsProvider,
		initialMaxDatagramSize protocol.ByteCount,
		qlogger qlogwriter.Recorder,
	) congestion.SendAlgorithmWithDebugInfos {
		return f(rttStats, initialMaxDatagramSize, qlogger)
	}
}
