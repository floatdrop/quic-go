package congestion

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// This file implements BBRv3 as specified in draft-ietf-ccwg-bbr-06.
// Function and field names follow the draft's pseudocode closely, and every
// non-obvious step cites the section it comes from, so that the implementation
// can be audited against the spec.
//
// Unlike Reno and CUBIC, BBR does not treat loss as the primary congestion
// signal. It measures the delivery rate and the minimum RTT of the path (see
// bbr_sampler.go), and paces at a gain-scaled multiple of that measured
// bandwidth. The congestion window is a bound on how far ahead of the ACK clock
// the sender may run, not the control variable.
//
// Deviations from the draft, all forced by the signals quic-go's congestion
// control interface provides:
//
//   - Spurious loss recovery, and the undo state that goes with it (§5.5.11),
//     is not implemented: quic-go does not report that a loss was spurious.
//   - ECN (§3.7) is not implemented: quic-go collapses CE marks into a single
//     boolean OnCongestionEvent call, which carries no CE fraction to respond to.
//   - Application-limited detection (§4.1.2.4) is inferred rather than
//     signalled. quic-go has no hook for "the application had nothing to send",
//     so we mark app-limited only where we can observe it: on a transmission
//     that restarts an idle connection, and during ProbeRTT. A flow that is
//     persistently app-limited at a rate below the path capacity — a live media
//     sender, for instance — will therefore hold a max_bw estimate closer to its
//     own send rate than the spec intends. See OnPacketSent.
//   - Send quantum (§5.6.3) is quic-go's business, not BBR's: the pacer already
//     allows a fixed burst. offloadBudget is derived from that burst.

const (
	// Gains. §5.3.1.1, §5.3.2, §5.3.3, §2.16.2.
	bbrStartupPacingGain = 2.77
	bbrDrainPacingGain   = 0.5
	bbrDefaultCwndGain   = 2.0
	bbrProbeRTTCwndGain  = 0.5
	bbrProbeBWDownGain   = 0.9
	bbrProbeBWUpGain     = 1.25

	// Core design parameters. §2.8.
	bbrLossThresh         = 0.02
	bbrBeta               = 0.7
	bbrHeadroom           = 0.15
	bbrMinPipeCwndPackets = 4

	// §5.6.2: pace 1% below bw, to drive the path toward shorter queues.
	bbrPacingMarginPercent = 1

	// Startup exit. §5.3.1.2, §5.3.1.3.
	bbrFullBWThreshold  = 1.25
	bbrFullBWCount      = 3
	bbrStartupFullLoss  = 6
	bbrMaxBwFilterLen   = 2  // §2.11, in ProbeBW cycles
	bbrExtraAckedLenNow = 1  // §5.5.9, in rounds, during Startup
	bbrExtraAckedLen    = 10 // §5.5.9, in rounds, after Startup

	// §2.16.
	bbrMinRTTFilterLen  = 10 * time.Second
	bbrProbeRTTDuration = 200 * time.Millisecond
	bbrProbeRTTInterval = 5 * time.Second

	// bbrInitialCwndPackets matches the Reno/CUBIC sender's initial window, so
	// that swapping controllers does not change handshake behaviour.
	bbrInitialCwndPackets = 32
)

// bbrInfiniteInflight stands in for the draft's "Infinity" for data volumes.
const bbrInfiniteInflight = protocol.MaxByteCount

// bbrInfiniteBandwidth stands in for the draft's "Infinity" for rates.
const bbrInfiniteBandwidth = Bandwidth(1<<62 - 1)

// bbrMode is the BBR state machine state. The draft models ProbeBW as one state
// with four phases; flattening the phases into the state saves carrying a
// second variable, and IsInAProbeBWState becomes a range check.
type bbrMode int

const (
	bbrStartup bbrMode = iota
	bbrDrain
	bbrProbeBWDown
	bbrProbeBWCruise
	bbrProbeBWRefill
	bbrProbeBWUp
	bbrProbeRTT
)

func (m bbrMode) String() string {
	switch m {
	case bbrStartup:
		return "Startup"
	case bbrDrain:
		return "Drain"
	case bbrProbeBWDown:
		return "ProbeBW_DOWN"
	case bbrProbeBWCruise:
		return "ProbeBW_CRUISE"
	case bbrProbeBWRefill:
		return "ProbeBW_REFILL"
	case bbrProbeBWUp:
		return "ProbeBW_UP"
	case bbrProbeRTT:
		return "ProbeRTT"
	default:
		return fmt.Sprintf("bbrMode(%d)", int(m))
	}
}

func (m bbrMode) isProbeBW() bool { return m >= bbrProbeBWDown && m <= bbrProbeBWUp }

// bbrAckPhase tracks what the ACK feedback currently arriving is telling us
// about the most recent bandwidth probe. §2.14.
type bbrAckPhase int

const (
	bbrAcksInit bbrAckPhase = iota
	bbrAcksRefilling
	bbrAcksProbeStarting
	bbrAcksProbeFeedback
	bbrAcksProbeStopping
)

type bbrSender struct {
	clock     Clock
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	pacer     *pacer
	sampler   *bbrSampler
	rand      utils.Rand

	mode     bbrMode
	ackPhase bbrAckPhase

	// Control parameters. §2.4-§2.6.
	pacingGain  float64
	cwndGain    float64
	pacingRate  Bandwidth
	cwnd        protocol.ByteCount
	priorCwnd   protocol.ByteCount // BBR.prior_cwnd, restored after loss/ProbeRTT
	maxInflight protocol.ByteCount

	// Data rate model. §2.9.1.
	maxBWFilter windowedMaxFilter
	bwShortterm Bandwidth
	bwLatest    Bandwidth
	cycleCount  int64 // virtual time for maxBWFilter, §5.5.6

	// Data volume model. §2.9.2.
	minRTT            time.Duration
	minRTTStamp       monotime.Time
	inflightLongterm  protocol.ByteCount
	inflightShortterm protocol.ByteCount
	inflightLatest    protocol.ByteCount

	// ACK aggregation. §2.12, §5.5.9.
	extraAckedFilter        windowedMaxFilter
	extraAcked              protocol.ByteCount
	extraAckedDelivered     protocol.ByteCount
	extraAckedIntervalStart monotime.Time

	// Round counting. §5.5.1.
	roundCount         int64
	nextRoundDelivered protocol.ByteCount
	roundStart         bool
	roundsSinceProbeUp int64
	lossRoundDelivered protocol.ByteCount
	lossRoundStart     bool
	isLossInRound      bool
	hasSeenLossInRound bool
	drainStartRound    int64

	// Startup. §2.13.
	fullBW        Bandwidth
	fullBWCount   int64
	fullBWNow     bool
	fullBWReached bool
	// startupLossEvents counts distinct lost packets since entering Startup,
	// for the high-loss exit criterion of §5.3.1.3.
	startupLossEvents int64

	// ProbeBW. §2.14.
	cycleStamp             monotime.Time
	bwProbeWait            time.Duration
	bwProbeUpRounds        int64
	bwProbeUpAcked         protocol.ByteCount
	probeUpAckedPerInc     protocol.ByteCount
	isBWProbeSample        bool
	prevProbeTooHigh       bool
	prevProbePrecautionary bool

	// ProbeRTT. §2.16.2.
	probeRTTMinDelay  time.Duration
	probeRTTMinStamp  monotime.Time
	probeRTTExpired   bool
	probeRTTDoneTime  monotime.Time
	probeRTTRoundDone bool
	idleRestart       bool

	// cwndLimited records whether the sender filled the congestion window at any
	// point in the current round. The draft calls this C.is_cwnd_limited and
	// expects the transport to provide it; quic-go does not, so we infer it at
	// transmit time. §5.3.3.9.
	cwndLimited bool

	inLossRecovery bool
	// recoveryStartRound is the round in which the current loss recovery began,
	// so that §5.3.1.3's "at least one full round trip in recovery" can be tested.
	recoveryStartRound int64

	maxDatagramSize     protocol.ByteCount
	initialCwnd         protocol.ByteCount
	maxCongestionWindow protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

// NewBBRSender creates a BBRv3 congestion controller.
func NewBBRSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *bbrSender {
	return newBBRSender(
		clock,
		rttStats,
		connStats,
		initialMaxDatagramSize,
		bbrInitialCwndPackets*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		qlogger,
	)
}

func newBBRSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize,
	initialCongestionWindow,
	maxCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *bbrSender {
	// OnInit(), §5.2.1.
	b := &bbrSender{
		clock:                   clock,
		rttStats:                rttStats,
		connStats:               connStats,
		sampler:                 newBBRSampler(),
		maxDatagramSize:         initialMaxDatagramSize,
		initialCwnd:             initialCongestionWindow,
		maxCongestionWindow:     maxCongestionWindow,
		cwnd:                    initialCongestionWindow,
		inflightLongterm:        bbrInfiniteInflight,
		inflightShortterm:       bbrInfiniteInflight,
		bwShortterm:             bbrInfiniteBandwidth,
		probeUpAckedPerInc:      bbrInfiniteInflight,
		minRTTStamp:             clock.Now(),
		probeRTTMinDelay:        bbrInfiniteRTT,
		probeRTTMinStamp:        clock.Now(),
		extraAckedIntervalStart: clock.Now(),
		qlogger:                 qlogger,
	}
	if rtt := rttStats.SmoothedRTT(); rtt > 0 {
		b.minRTT = rtt
	}
	// The pacer must run at exactly the rate BBR computes: pacingRate already
	// carries the gain and the 1% margin, so the headroom newPacer adds for
	// Reno would silently override every gain in the state machine.
	b.pacer = newExactPacer(func() Bandwidth { return b.pacingRate })
	b.pacer.SetMaxDatagramSize(initialMaxDatagramSize)
	b.enterStartup()
	b.initPacingRate()
	return b
}

// bbrInfiniteRTT stands in for the draft's "Infinity" min RTT.
const bbrInfiniteRTT = time.Duration(1<<62 - 1)

// ---- SendAlgorithm ----

func (b *bbrSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// MaybeExitSlowStart is a no-op: BBR leaves Startup on its own bandwidth-plateau
// and loss estimators (§5.3.1), not on quic-go's HyStart-style hint.
func (b *bbrSender) MaybeExitSlowStart() {}

func (b *bbrSender) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	// bytesInFlight already includes this packet, so equality means the
	// connection had nothing in flight before it: this send restarts an idle
	// connection. That is the one application-limited condition quic-go's
	// interface lets us observe (§4.1.2.4), and it is also the trigger for
	// HandleRestartFromIdle (§5.4.1).
	if isRetransmittable && bytesInFlight == bytes {
		b.sampler.MarkAppLimited(bytesInFlight - bytes)
		b.handleRestartFromIdle(sentTime)
	}
	b.pacer.SentPacket(sentTime, bytes)
	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
	if isRetransmittable && bytesInFlight >= b.cwnd {
		b.cwndLimited = true
	}
}

// OnPacketAcked runs the per-ACK steps of §5.2.3. quic-go calls it once per
// acknowledged packet rather than once per ACK frame; see bbr_sampler.go for
// why that is safe for the delivery rate estimate.
func (b *bbrSender) OnPacketAcked(
	number protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	rs, ok := b.sampler.OnPacketAcked(eventTime, number, b.minRTT)
	if !ok {
		return
	}
	inflight := max(priorInFlight-ackedBytes, 0)

	// UpdateModelAndState(), §5.2.3.
	b.updateLatestDeliverySignals(rs)
	b.updateCongestionSignals(rs)
	b.updateACKAggregation(rs, eventTime)
	b.checkFullBWReached(rs)
	b.checkStartupDone()
	b.checkDrainDone(inflight)
	b.updateProbeBWCyclePhase(rs, inflight, eventTime)
	b.updateMinRTT(eventTime)
	b.checkProbeRTT(rs, inflight, eventTime)
	b.advanceLatestDeliverySignals(rs)

	// UpdateControlParameters(), §5.2.3.
	b.setPacingRate()
	b.setCwnd(rs)
	b.maybeQlogStateChange()
}

// OnCongestionEvent implements the per-loss steps of §5.2.4.
func (b *bbrSender) OnCongestionEvent(
	number protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	b.connStats.PacketsLost.Add(1)
	b.connStats.BytesLost.Add(uint64(lostBytes))

	p, ok := b.sampler.OnPacketLost(number, lostBytes)
	b.handleLostPacket(p, ok)

	if !b.inLossRecovery {
		b.inLossRecovery = true
		b.recoveryStartRound = b.roundCount
		b.saveCwnd()
	}
}

// OnRetransmissionTimeout implements the RTO response of §5.6.4.4.
func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	b.saveCwnd()
	// Allow exactly one packet out, then rebuild through the normal SetCwnd path.
	b.cwnd = b.maxDatagramSize
}

func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	cwndIsMinCwnd := b.cwnd == b.minCwnd()
	b.maxDatagramSize = s
	if cwndIsMinCwnd {
		b.cwnd = b.minCwnd()
	}
	b.pacer.SetMaxDatagramSize(s)
	b.maxCongestionWindow = protocol.MaxCongestionWindowPackets * s
}

// ---- SendAlgorithmWithDebugInfos ----

// InSlowStart reports Startup, BBR's analogue of slow start.
func (b *bbrSender) InSlowStart() bool { return b.mode == bbrStartup }

func (b *bbrSender) InRecovery() bool { return b.inLossRecovery }

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount { return b.cwnd }

// BandwidthEstimate returns BBR.bw, the rate the model considers safe to send
// at. It is exported for tests and for callers that want the model's view of
// path capacity rather than cwnd/RTT.
func (b *bbrSender) BandwidthEstimate() Bandwidth { return b.bw() }

// ---- Network path model: data rate (§5.5.2-§5.5.6) ----

func (b *bbrSender) maxBW() Bandwidth { return Bandwidth(b.maxBWFilter.Best()) }

// bw is BBR.bw = min(max_bw, bw_shortterm). §5.5.10.3 BoundBWForModel.
func (b *bbrSender) bw() Bandwidth {
	return min(b.maxBW(), b.bwShortterm)
}

// updateRound implements UpdateRound(), §5.5.1. A packet-timed round trip ends
// when we receive an ACK for a packet sent after the round's sentinel.
func (b *bbrSender) updateRound(rs bbrRateSample) {
	if rs.priorDelivered >= b.nextRoundDelivered {
		b.startRound()
		b.roundCount++
		b.roundsSinceProbeUp++
		b.roundStart = true
		b.cwndLimited = false
		b.startupLossEvents = 0
	} else {
		b.roundStart = false
	}
}

func (b *bbrSender) startRound() { b.nextRoundDelivered = b.sampler.delivered }

// updateMaxBW implements UpdateMaxBw(), §5.5.5.
func (b *bbrSender) updateMaxBW(rs bbrRateSample) {
	b.updateRound(rs)
	if !rs.hasRate {
		return
	}
	// An application-limited sample can only raise max_bw, never lower it: it
	// measures the application's rate, not the path's. §5.5.4.
	if rs.deliveryRate >= b.maxBW() || !rs.isAppLimited {
		b.maxBWFilter.Update(int64(rs.deliveryRate), b.cycleCount, bbrMaxBwFilterLen)
	}
}

func (b *bbrSender) advanceMaxBWFilter() { b.cycleCount++ }

// ---- Congestion signals (§5.5.10.3) ----

// updateLatestDeliverySignals implements UpdateLatestDeliverySignals().
func (b *bbrSender) updateLatestDeliverySignals(rs bbrRateSample) {
	b.lossRoundStart = false
	b.bwLatest = max(b.bwLatest, rs.deliveryRate)
	b.inflightLatest = max(b.inflightLatest, rs.delivered)
	if rs.priorDelivered >= b.lossRoundDelivered {
		b.lossRoundDelivered = b.sampler.delivered
		b.lossRoundStart = true
	}
}

// advanceLatestDeliverySignals implements AdvanceLatestDeliverySignals().
func (b *bbrSender) advanceLatestDeliverySignals(rs bbrRateSample) {
	if b.lossRoundStart {
		b.bwLatest = rs.deliveryRate
		b.inflightLatest = rs.delivered
	}
}

func (b *bbrSender) resetCongestionSignals() {
	b.isLossInRound = false
	b.bwLatest = 0
	b.inflightLatest = 0
}

// updateCongestionSignals implements UpdateCongestionSignals().
func (b *bbrSender) updateCongestionSignals(rs bbrRateSample) {
	b.updateMaxBW(rs)
	if !b.lossRoundStart {
		return
	}
	b.adaptLowerBoundsFromCongestion()
	b.isLossInRound = false
}

// adaptLowerBoundsFromCongestion runs once per round trip. While probing for
// bandwidth the response to loss is inflight_longterm (§5.5.10.2); the
// short-term bounds are for the states that are not probing.
func (b *bbrSender) adaptLowerBoundsFromCongestion() {
	if b.isProbingBW() {
		return
	}
	if b.isLossInRound {
		b.initLowerBounds()
		b.lossLowerBounds()
	}
}

func (b *bbrSender) initLowerBounds() {
	if b.bwShortterm == bbrInfiniteBandwidth {
		b.bwShortterm = b.maxBW()
	}
	if b.inflightShortterm == bbrInfiniteInflight {
		b.inflightShortterm = b.cwnd
	}
}

func (b *bbrSender) lossLowerBounds() {
	b.bwShortterm = max(b.bwLatest, Bandwidth(float64(b.bwShortterm)*bbrBeta))
	b.inflightShortterm = max(b.inflightLatest, protocol.ByteCount(float64(b.inflightShortterm)*bbrBeta))
}

func (b *bbrSender) resetShortTermModel() {
	b.bwShortterm = bbrInfiniteBandwidth
	b.inflightShortterm = bbrInfiniteInflight
}

func (b *bbrSender) isProbingBW() bool {
	return b.mode == bbrStartup || b.mode == bbrProbeBWRefill || b.mode == bbrProbeBWUp
}

// ---- ACK aggregation (§5.5.9) ----

func (b *bbrSender) updateACKAggregation(rs bbrRateSample, now monotime.Time) {
	interval := now.Sub(b.extraAckedIntervalStart)
	var expected protocol.ByteCount
	if interval > 0 {
		expected = bandwidthToBytes(b.bw(), interval)
	}
	// An ACK rate at or below the expected rate means the aggregation episode
	// ended; restart the interval here.
	if b.extraAckedDelivered <= expected {
		b.extraAckedDelivered = 0
		b.extraAckedIntervalStart = now
		expected = 0
	}
	b.extraAckedDelivered += rs.newlyAcked
	extra := min(b.extraAckedDelivered-expected, b.cwnd)

	filterLen := int64(bbrExtraAckedLenNow)
	if b.fullBWReached {
		filterLen = bbrExtraAckedLen
	}
	b.extraAckedFilter.Update(int64(extra), b.roundCount, filterLen)
	b.extraAcked = protocol.ByteCount(b.extraAckedFilter.Best())
}

// ---- Startup (§5.3.1) ----

func (b *bbrSender) enterStartup() {
	b.setMode(bbrStartup)
	b.pacingGain = bbrStartupPacingGain
	b.cwndGain = bbrDefaultCwndGain
}

func (b *bbrSender) resetFullBW() {
	b.fullBW = 0
	b.fullBWCount = 0
	b.fullBWNow = false
}

// checkFullBWReached implements CheckFullBWReached(), §5.3.1.2: three rounds
// without a 25% increase in delivery rate means the pipe is full.
func (b *bbrSender) checkFullBWReached(rs bbrRateSample) {
	if b.fullBWNow || !b.roundStart || rs.isAppLimited {
		return
	}
	if rs.deliveryRate >= Bandwidth(float64(b.fullBW)*bbrFullBWThreshold) {
		b.resetFullBW()
		b.fullBW = rs.deliveryRate
		return
	}
	b.fullBWCount++
	b.fullBWNow = b.fullBWCount >= bbrFullBWCount
	if b.fullBWNow {
		b.fullBWReached = true
	}
}

func (b *bbrSender) checkStartupDone() {
	if b.mode == bbrStartup && b.fullBWReached {
		b.enterDrain()
	}
}

// checkStartupHighLoss implements §5.3.1.3. quic-go always has selective
// acknowledgements, so all three criteria apply: we must be in recovery for a
// full round, the round's loss rate must exceed LossThresh, and at least
// bbrStartupFullLoss distinct packets must have been lost in the round.
func (b *bbrSender) checkStartupHighLoss(lossEventsThisRound int64, rs bbrRateSample) {
	if b.mode != bbrStartup || !b.inLossRecovery {
		return
	}
	if b.roundCount <= b.recoveryStartRound {
		return // not yet a full packet-timed round trip in recovery
	}
	if lossEventsThisRound < bbrStartupFullLoss {
		return
	}
	if rs.txInFlight == 0 || float64(rs.lost) <= float64(rs.txInFlight)*bbrLossThresh {
		return
	}
	b.fullBWReached = true
	b.inflightLongterm = max(b.bdp(), b.inflightLatest)
}

// ---- Drain (§5.3.2) ----

func (b *bbrSender) enterDrain() {
	b.setMode(bbrDrain)
	b.pacingGain = bbrDrainPacingGain
	b.cwndGain = bbrDefaultCwndGain
	b.drainStartRound = b.roundCount
}

// checkDrainDone implements CheckDrainDone(), §5.3.2. Drain normally completes
// within a round; the round-count escape hatch covers a Startup that
// overestimated bandwidth against competing flows.
func (b *bbrSender) checkDrainDone(inflight protocol.ByteCount) {
	if b.mode != bbrDrain {
		return
	}
	if inflight <= b.inflight(b.maxBW(), 1.0) || b.roundCount > b.drainStartRound+3 {
		b.enterProbeBW()
	}
}

// ---- ProbeBW (§5.3.3) ----

func (b *bbrSender) enterProbeBW() {
	b.cwndGain = bbrDefaultCwndGain
	b.startProbeBWDown()
}

func (b *bbrSender) startProbeBWDown() {
	b.resetCongestionSignals()
	b.probeUpAckedPerInc = bbrInfiniteInflight
	b.pickProbeWait()
	b.cycleStamp = b.clock.Now()
	b.ackPhase = bbrAcksProbeStopping
	b.startRound()
	b.setMode(bbrProbeBWDown)
	b.pacingGain = bbrProbeBWDownGain
	b.cwndGain = bbrDefaultCwndGain
}

func (b *bbrSender) startProbeBWCruise() {
	b.setMode(bbrProbeBWCruise)
	b.pacingGain = 1.0
	b.cwndGain = bbrDefaultCwndGain
}

func (b *bbrSender) startProbeBWRefill() {
	b.resetShortTermModel()
	b.bwProbeUpRounds = 0
	b.bwProbeUpAcked = 0
	b.prevProbePrecautionary = false
	b.ackPhase = bbrAcksRefilling
	b.startRound()
	b.setMode(bbrProbeBWRefill)
	b.pacingGain = 1.0
	b.cwndGain = bbrDefaultCwndGain
}

func (b *bbrSender) startProbeBWUp(rs bbrRateSample) {
	b.ackPhase = bbrAcksProbeStarting
	b.startRound()
	b.resetFullBW()
	b.fullBW = rs.deliveryRate
	b.setMode(bbrProbeBWUp)
	b.pacingGain = bbrProbeBWUpGain
	b.cwndGain = bbrDefaultCwndGain
	b.raiseInflightLongtermSlope()
}

// pickProbeWait implements PickProbeWait(), §5.3.3.8: randomize both the round
// and wall-clock bounds so that competing flows do not synchronize their probes.
func (b *bbrSender) pickProbeWait() {
	b.roundsSinceProbeUp = int64(b.rand.Int31n(2))
	b.bwProbeWait = 2*time.Second + time.Duration(b.rand.Int31n(1000))*time.Millisecond
}

// updateProbeBWCyclePhase implements UpdateProbeBWCyclePhase(), §5.3.3.9.
func (b *bbrSender) updateProbeBWCyclePhase(rs bbrRateSample, inflight protocol.ByteCount, now monotime.Time) {
	if !b.fullBWReached {
		return
	}
	if b.adaptLongTermModel(rs) {
		return
	}
	if !b.mode.isProbeBW() {
		return
	}
	switch b.mode {
	case bbrStartup, bbrDrain, bbrProbeRTT:
		// Unreachable: the isProbeBW check above already returned.
	case bbrProbeBWDown:
		if b.isTimeToProbeBW(rs, now) {
			return
		}
		if b.isTimeToCruise(inflight) {
			b.startProbeBWCruise()
		}
	case bbrProbeBWCruise:
		if b.isTimeToProbeBW(rs, now) {
			return
		}
	case bbrProbeBWRefill:
		// One full round at the estimated bandwidth refills the pipe; then probe.
		if b.roundStart {
			b.isBWProbeSample = true
			b.startProbeBWUp(rs)
		}
	case bbrProbeBWUp:
		if b.isTimeToGoDown(rs, inflight) {
			b.prevProbeTooHigh = false
			b.startProbeBWDown()
		}
	}
}

// isTimeToProbeBW implements IsTimeToProbeBW(), §5.3.3.9.
func (b *bbrSender) isTimeToProbeBW(_ bbrRateSample, now monotime.Time) bool {
	if b.hasElapsedInPhase(b.bwProbeWait, now) || b.isRenoCoexistenceProbeTime() {
		b.startProbeBWRefill()
		return true
	}
	return false
}

func (b *bbrSender) hasElapsedInPhase(interval time.Duration, now monotime.Time) bool {
	return now.After(b.cycleStamp.Add(interval))
}

// isRenoCoexistenceProbeTime makes BBR probe at least as often as a Reno flow
// would grow its window, so the two converge to a fair share. §5.3.3.8.2.
func (b *bbrSender) isRenoCoexistenceProbeTime() bool {
	renoRounds := b.targetInflight() / b.maxDatagramSize
	rounds := min(renoRounds, 63)
	return b.roundsSinceProbeUp >= int64(rounds)
}

// targetInflight is the volume we want in flight: the estimated BDP, unless
// congestion has already cut cwnd below it. §5.3.3.8.
func (b *bbrSender) targetInflight() protocol.ByteCount {
	return min(b.bdp(), b.cwnd)
}

// isTimeToCruise implements IsTimeToCruise(), §5.3.3.9.
func (b *bbrSender) isTimeToCruise(inflight protocol.ByteCount) bool {
	if inflight > b.inflightWithHeadroom() {
		return false // not enough headroom left for other flows
	}
	if inflight > b.inflight(b.maxBW(), 1.0) {
		return false // still above the estimated BDP
	}
	return true
}

// isTimeToGoDown implements IsTimeToGoDown(), §5.3.3.9.
func (b *bbrSender) isTimeToGoDown(rs bbrRateSample, inflight protocol.ByteCount) bool {
	// Precautionary bandwidth probing, deceleration half: the previous probe
	// overshot, so stop as soon as we reach that level rather than holding the
	// bottleneck buffer full for a whole round. §5.3.3.6.
	if b.prevProbeTooHigh && inflight >= b.inflightLongterm {
		b.prevProbePrecautionary = true
		return true
	}
	if b.cwndLimited && b.cwnd >= b.inflightLongterm {
		// We are held back by inflight_longterm rather than by the path, so the
		// plateau estimator is not measuring the path. Restart it.
		b.resetFullBW()
		b.fullBW = rs.deliveryRate
	} else if b.fullBWNow {
		return true
	}
	return false
}

// inflightWithHeadroom implements InflightWithHeadroom(), §5.3.3.9: leave some
// of the bottleneck buffer free so competing flows can converge.
func (b *bbrSender) inflightWithHeadroom() protocol.ByteCount {
	if b.inflightLongterm == bbrInfiniteInflight {
		return bbrInfiniteInflight
	}
	headroom := max(b.maxDatagramSize, protocol.ByteCount(bbrHeadroom*float64(b.inflightLongterm)))
	return max(b.inflightLongterm-headroom, b.minCwnd())
}

// raiseInflightLongtermSlope implements RaiseInflightLongtermSlope(), §5.3.3.9:
// each round of ProbeBW_UP doubles the rate at which inflight_longterm grows.
func (b *bbrSender) raiseInflightLongtermSlope() {
	growthThisRound := protocol.ByteCount(1) << min(b.bwProbeUpRounds, 30)
	b.bwProbeUpRounds = min(b.bwProbeUpRounds+1, 30)
	b.probeUpAckedPerInc = max(b.cwnd/growthThisRound, b.maxDatagramSize)
}

// probeInflightLongtermUpward implements ProbeInflightLongtermUpward(), §5.3.3.9.
func (b *bbrSender) probeInflightLongtermUpward(rs bbrRateSample) {
	if !b.cwndLimited || b.cwnd < b.inflightLongterm {
		return // not actually using the limit, so don't raise it
	}
	b.bwProbeUpAcked += rs.newlyAcked
	if b.probeUpAckedPerInc > 0 && b.bwProbeUpAcked >= b.probeUpAckedPerInc {
		delta := b.bwProbeUpAcked / b.probeUpAckedPerInc
		b.bwProbeUpAcked -= delta * b.probeUpAckedPerInc
		b.inflightLongterm += delta * b.maxDatagramSize
	}
	if b.roundStart {
		b.raiseInflightLongtermSlope()
	}
}

// adaptLongTermModel implements AdaptLongTermModel(), §5.3.3.9. It returns true
// if it decided a state transition.
func (b *bbrSender) adaptLongTermModel(rs bbrRateSample) bool {
	if b.ackPhase == bbrAcksProbeStarting && b.roundStart {
		b.ackPhase = bbrAcksProbeFeedback
	}
	if b.ackPhase == bbrAcksProbeStopping && b.roundStart {
		b.isBWProbeSample = false
		b.ackPhase = bbrAcksInit
		if b.mode.isProbeBW() && !rs.isAppLimited {
			b.advanceMaxBWFilter()
		}
		// Precautionary bandwidth probing, acceleration half: a full round of
		// probe feedback with no excess loss means we can probe again straight
		// away, skipping cruise. §5.3.3.6.
		if b.mode.isProbeBW() && b.prevProbePrecautionary && !b.prevProbeTooHigh {
			b.startProbeBWRefill()
			return true
		}
	}
	if !b.isInflightTooHigh(rs) {
		if b.inflightLongterm == bbrInfiniteInflight {
			return false
		}
		if rs.txInFlight > b.inflightLongterm {
			b.inflightLongterm = rs.txInFlight
		}
		if b.mode == bbrProbeBWUp {
			b.probeInflightLongtermUpward(rs)
		}
	}
	return false
}

// ---- Loss response (§5.5.10) ----

// isInflightTooHigh implements IsInflightTooHigh(), §5.5.10.2.
func (b *bbrSender) isInflightTooHigh(rs bbrRateSample) bool {
	return float64(rs.lost) > float64(rs.txInFlight)*bbrLossThresh
}

// handleInflightTooHigh implements HandleInflightTooHigh(), §5.5.10.2.
func (b *bbrSender) handleInflightTooHigh(rs bbrRateSample) {
	b.prevProbeTooHigh = true
	b.isBWProbeSample = false // react only once per bandwidth probe
	if !rs.isAppLimited {
		// The Beta floor keeps BBR from cutting harder than CUBIC's 0.7x.
		b.inflightLongterm = max(rs.txInFlight, protocol.ByteCount(float64(b.targetInflight())*bbrBeta))
	}
	if b.mode == bbrProbeBWUp {
		b.startProbeBWDown()
	}
}

// noteLoss implements NoteLoss(), §5.5.10.2.
func (b *bbrSender) noteLoss() {
	if !b.isLossInRound {
		b.lossRoundDelivered = b.sampler.delivered
	}
	b.isLossInRound = true
	b.hasSeenLossInRound = true
}

// lossEventsInRound counts distinct loss events in the current round, for the
// Startup high-loss exit criterion (§5.3.1.3).
func (b *bbrSender) lossEventsInRound() int64 { return b.startupLossEvents }

// handleLostPacket implements HandleLostPacket(), §5.5.10.2.
//
// One deviation: the draft evaluates the Startup high-loss exit from the ACK
// path, inside CheckStartupDone(). We evaluate it here instead, because this is
// where the lost packet's tx_in_flight is available. The criteria are the same,
// and checking at loss time reacts a round trip sooner.
func (b *bbrSender) handleLostPacket(p bbrPacketState, tracked bool) {
	b.noteLoss()
	if b.mode == bbrStartup {
		b.startupLossEvents++
	}
	if !tracked {
		return
	}
	if !b.isBWProbeSample && b.mode != bbrStartup {
		return // not a packet sent while probing for bandwidth
	}
	rs := bbrRateSample{
		txInFlight:   p.txInFlight,
		lost:         b.sampler.lost - p.lost,
		isAppLimited: p.isAppLimited,
	}
	if b.mode == bbrStartup {
		b.checkStartupHighLoss(b.lossEventsInRound(), rs)
		b.checkStartupDone()
		return
	}
	if b.isInflightTooHigh(rs) {
		rs.txInFlight = b.inflightAtLoss(p, rs)
		b.handleInflightTooHigh(rs)
	}
}

// inflightAtLoss implements InflightAtLoss(), §5.5.10.2: solve for the prefix of
// this packet at which the loss rate crossed LossThresh. Loss detection is
// delayed by reordering tolerance, so the inflight recorded when the packet was
// sent overstates how much was safely in flight.
func (b *bbrSender) inflightAtLoss(p bbrPacketState, rs bbrRateSample) protocol.ByteCount {
	inflightPrev := rs.txInFlight - p.size
	lostPrev := rs.lost - p.size
	lostPrefix := (bbrLossThresh*float64(inflightPrev) - float64(lostPrev)) / (1 - bbrLossThresh)
	if lostPrefix < 0 {
		lostPrefix = 0
	}
	return inflightPrev + protocol.ByteCount(lostPrefix)
}

// ---- min RTT and ProbeRTT (§5.3.4, §5.5.7) ----

func (b *bbrSender) bdp() protocol.ByteCount {
	return b.bdpMultiple(b.bw(), 1.0)
}

// bdpMultiple implements BDPMultiple(), §5.6.4.2.
func (b *bbrSender) bdpMultiple(bw Bandwidth, gain float64) protocol.ByteCount {
	if b.minRTT == 0 || b.minRTT == bbrInfiniteRTT {
		return b.initialCwnd // no valid RTT samples yet
	}
	bdp := bandwidthToBytes(bw, b.minRTT)
	return protocol.ByteCount(gain * float64(bdp))
}

// inflight implements Inflight(gain), §5.6.4.2.
func (b *bbrSender) inflight(bw Bandwidth, gain float64) protocol.ByteCount {
	return b.quantizationBudget(b.bdpMultiple(bw, gain))
}

// quantizationBudget implements QuantizationBudget(), §5.6.4.2.
func (b *bbrSender) quantizationBudget(inflightCap protocol.ByteCount) protocol.ByteCount {
	inflightCap = max(inflightCap, b.offloadBudget())
	inflightCap = max(inflightCap, b.minCwnd())
	if b.mode == bbrProbeBWUp {
		inflightCap += 2 * b.maxDatagramSize
	}
	return inflightCap
}

// offloadBudget is the QUIC form of §5.5.8.2. quic-go's pacer releases up to
// maxBurstSizePackets datagrams at once, so that burst is the volume we must
// allow in flight to keep the link busy between pacer wakeups.
func (b *bbrSender) offloadBudget() protocol.ByteCount {
	return maxBurstSizePackets * b.maxDatagramSize
}

func (b *bbrSender) minCwnd() protocol.ByteCount {
	return bbrMinPipeCwndPackets * b.maxDatagramSize
}

// updateMinRTT implements UpdateMinRTT(), §5.3.4.3.
func (b *bbrSender) updateMinRTT(now monotime.Time) {
	b.probeRTTExpired = now.After(b.probeRTTMinStamp.Add(bbrProbeRTTInterval))
	rtt := b.rttStats.LatestRTT()
	if rtt > 0 && (rtt < b.probeRTTMinDelay || b.probeRTTExpired) {
		b.probeRTTMinDelay = rtt
		b.probeRTTMinStamp = now
	}
	minRTTExpired := now.After(b.minRTTStamp.Add(bbrMinRTTFilterLen))
	if b.probeRTTMinDelay != bbrInfiniteRTT && (b.probeRTTMinDelay < b.minRTT || b.minRTT == 0 || minRTTExpired) {
		b.minRTT = b.probeRTTMinDelay
		b.minRTTStamp = b.probeRTTMinStamp
	}
}

// checkProbeRTT implements CheckProbeRTT(), §5.3.4.3.
func (b *bbrSender) checkProbeRTT(rs bbrRateSample, inflight protocol.ByteCount, now monotime.Time) {
	if b.mode != bbrProbeRTT && b.probeRTTExpired && !b.idleRestart {
		b.enterProbeRTT()
		b.saveCwnd()
		b.probeRTTDoneTime = 0
		b.ackPhase = bbrAcksProbeStopping
		b.startRound()
	}
	if b.mode == bbrProbeRTT {
		b.handleProbeRTT(inflight, now)
	}
	if rs.delivered > 0 {
		b.idleRestart = false
	}
}

func (b *bbrSender) enterProbeRTT() {
	b.setMode(bbrProbeRTT)
	b.pacingGain = 1.0
	b.cwndGain = bbrProbeRTTCwndGain
}

// handleProbeRTT implements HandleProbeRTT(), §5.3.4.3.
func (b *bbrSender) handleProbeRTT(inflight protocol.ByteCount, now monotime.Time) {
	// Rate samples taken at the deliberately reduced ProbeRTT window measure our
	// own restraint, not the path, so they must not lower max_bw.
	b.sampler.MarkAppLimited(inflight)

	if b.probeRTTDoneTime.IsZero() && inflight <= b.probeRTTCwnd() {
		b.probeRTTDoneTime = now.Add(bbrProbeRTTDuration)
		b.probeRTTRoundDone = false
		b.startRound()
		return
	}
	if !b.probeRTTDoneTime.IsZero() {
		if b.roundStart {
			b.probeRTTRoundDone = true
		}
		if b.probeRTTRoundDone {
			b.checkProbeRTTDone(now)
		}
	}
}

// checkProbeRTTDone implements CheckProbeRTTDone(), §5.3.4.3.
func (b *bbrSender) checkProbeRTTDone(now monotime.Time) {
	if b.probeRTTDoneTime.IsZero() || !now.After(b.probeRTTDoneTime) {
		return
	}
	b.probeRTTMinStamp = now // schedule the next ProbeRTT
	b.restoreCwnd()
	b.exitProbeRTT()
}

// exitProbeRTT implements ExitProbeRTT(), §5.3.4.4.
func (b *bbrSender) exitProbeRTT() {
	b.resetShortTermModel()
	if b.fullBWReached {
		// Inflight is already below the BDP, so skip DOWN and cruise directly —
		// but reset the probing clock via startProbeBWDown first.
		b.startProbeBWDown()
		b.startProbeBWCruise()
	} else {
		b.enterStartup()
	}
}

// probeRTTCwnd implements ProbeRTTCwnd(), §5.6.4.5.
func (b *bbrSender) probeRTTCwnd() protocol.ByteCount {
	return max(b.bdpMultiple(b.bw(), bbrProbeRTTCwndGain), b.minCwnd())
}

// ---- Restarting from idle (§5.4.1) ----

func (b *bbrSender) handleRestartFromIdle(now monotime.Time) {
	b.idleRestart = true
	b.extraAckedIntervalStart = now
	if b.mode.isProbeBW() {
		// Return to rate balance immediately by pacing at exactly bw.
		b.setPacingRateWithGain(1.0)
	} else if b.mode == bbrProbeRTT {
		b.checkProbeRTTDone(now)
	}
}

// ---- Control parameters (§5.6) ----

// initPacingRate implements InitPacingRate(), §5.6.2.
func (b *bbrSender) initPacingRate() {
	rtt := b.rttStats.SmoothedRTT()
	if rtt == 0 {
		rtt = time.Millisecond
	}
	nominal := BandwidthFromDelta(b.initialCwnd, rtt)
	b.pacingRate = Bandwidth(bbrStartupPacingGain * float64(nominal))
}

// setPacingRateWithGain implements SetPacingRateWithGain(), §5.6.2. Until the
// pipe is estimated full the pacing rate only ever increases, so that
// application-limited samples cannot stall the search for bandwidth.
func (b *bbrSender) setPacingRateWithGain(gain float64) {
	bw := b.bw()
	if bw == 0 {
		return
	}
	rate := Bandwidth(gain * float64(bw) * (100 - bbrPacingMarginPercent) / 100)
	if b.fullBWReached || rate > b.pacingRate {
		b.pacingRate = rate
	}
}

func (b *bbrSender) setPacingRate() { b.setPacingRateWithGain(b.pacingGain) }

// updateMaxInflight implements UpdateMaxInflight(), §5.6.4.2.
func (b *bbrSender) updateMaxInflight() {
	inflightCap := b.bdpMultiple(b.bw(), b.cwndGain)
	inflightCap += b.extraAcked
	b.maxInflight = b.quantizationBudget(inflightCap)
}

// setCwnd implements SetCwnd(), §5.6.4.6.
func (b *bbrSender) setCwnd(rs bbrRateSample) {
	b.updateMaxInflight()
	if b.fullBWReached {
		b.cwnd = min(b.cwnd+rs.newlyAcked, b.maxInflight)
	} else if b.cwnd < b.maxInflight || b.sampler.delivered < b.initialCwnd {
		// Before the model is trusted, grow without bounding to max_inflight.
		b.cwnd += rs.newlyAcked
	}
	b.cwnd = max(b.cwnd, b.minCwnd())
	b.boundCwndForProbeRTT()
	b.boundCwndForModel()
	b.cwnd = min(b.cwnd, b.maxCongestionWindow)

	// Loss recovery ends once the model-bounded cwnd has been re-established.
	if b.inLossRecovery && !b.hasSeenLossInRound && b.roundStart {
		b.inLossRecovery = false
		b.restoreCwnd()
		b.startupLossEvents = 0
	}
	if b.roundStart {
		b.hasSeenLossInRound = false
	}
}

func (b *bbrSender) boundCwndForProbeRTT() {
	if b.mode == bbrProbeRTT {
		b.cwnd = min(b.cwnd, b.probeRTTCwnd())
	}
}

// boundCwndForModel implements BoundCwndForModel(), §5.6.4.7.
func (b *bbrSender) boundCwndForModel() {
	volumeCap := bbrInfiniteInflight
	switch {
	case b.mode.isProbeBW() && b.mode != bbrProbeBWCruise:
		volumeCap = b.inflightLongterm
	case b.mode == bbrProbeRTT || b.mode == bbrProbeBWCruise:
		volumeCap = b.inflightWithHeadroom()
	}
	volumeCap = min(volumeCap, b.inflightShortterm)
	volumeCap = max(volumeCap, b.minCwnd())
	b.cwnd = min(b.cwnd, volumeCap)
}

// saveCwnd implements SaveCwnd(), §5.6.4.4.
func (b *bbrSender) saveCwnd() {
	if !b.inLossRecovery && b.mode != bbrProbeRTT {
		b.priorCwnd = b.cwnd
	} else {
		b.priorCwnd = max(b.priorCwnd, b.cwnd)
	}
}

// restoreCwnd implements RestoreCwnd(), §5.6.4.4.
func (b *bbrSender) restoreCwnd() { b.cwnd = max(b.cwnd, b.priorCwnd) }

// ---- qlog ----

func (b *bbrSender) setMode(m bbrMode) { b.mode = m }

// maybeQlogStateChange maps BBR's state machine onto qlog's congestion state
// vocabulary, which was defined for Reno/CUBIC: Startup is reported as slow
// start, every other state as congestion avoidance, with recovery and
// application-limited taking precedence when they apply.
func (b *bbrSender) maybeQlogStateChange() {
	if b.qlogger == nil {
		return
	}
	var state qlog.CongestionState
	switch {
	case b.inLossRecovery:
		state = qlog.CongestionStateRecovery
	case b.sampler.isAppLimited():
		state = qlog.CongestionStateApplicationLimited
	case b.mode == bbrStartup:
		state = qlog.CongestionStateSlowStart
	default:
		state = qlog.CongestionStateCongestionAvoidance
	}
	if state == b.lastState {
		return
	}
	b.lastState = state
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})
}

// bandwidthToBytes converts a rate and a duration into a volume of data.
func bandwidthToBytes(bw Bandwidth, d time.Duration) protocol.ByteCount {
	if bw == 0 || d <= 0 {
		return 0
	}
	if bw == bbrInfiniteBandwidth {
		return bbrInfiniteInflight
	}
	bytesPerSecond := uint64(bw) / uint64(BytesPerSecond)
	secs := uint64(d) / uint64(time.Second)
	nanos := uint64(d) % uint64(time.Second)
	// Split the multiplication so that a high rate over a multi-second interval
	// does not overflow the intermediate product.
	whole := bytesPerSecond * secs
	frac := bytesPerSecond * nanos / uint64(time.Second)
	total := whole + frac
	if total > uint64(protocol.MaxByteCount) || whole > uint64(protocol.MaxByteCount)-frac {
		return protocol.MaxByteCount
	}
	return protocol.ByteCount(total)
}
