package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// An RTTStatsProvider gives a congestion controller read access to the
// connection's RTT estimates. It is the read-only subset of utils.RTTStats that
// congestion control needs, so that a controller can be supplied from outside
// this module without exposing the mutating half.
type RTTStatsProvider interface {
	MinRTT() time.Duration
	LatestRTT() time.Duration
	SmoothedRTT() time.Duration
}

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// An ApplicationLimitedHandler is a SendAlgorithm that wants to be told when the
// connection is application-limited: the application had nothing left to send
// even though the congestion window still had room.
//
// draft-ietf-ccwg-bbr-06 §4.1.2.4 calls this CheckIfApplicationLimited(). A
// delivery rate measured over such a period describes the application, not the
// path, so a model-based controller must not treat it as evidence about the
// network. Loss-based controllers have no use for it, which is why this is a
// separate optional interface rather than a method on SendAlgorithm.
type ApplicationLimitedHandler interface {
	// OnApplicationLimited is called with the volume of data in flight at the
	// moment the application ran dry.
	OnApplicationLimited(bytesInFlight protocol.ByteCount)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}
