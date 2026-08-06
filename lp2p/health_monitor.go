package lp2p

import (
	"net"
	"sync"
	"time"

	"github.com/cometbft/cometbft/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

// HealthSnapshot mirrors the six inputs to IsP2PQualityHealthy in
// spec/core/EngramFSM.tla:76-81 of the engram-sovereign-fsm repo
// (SubnetDiversity, ActiveAnchors, CleanPeers, peer_churn_rate,
// avg_peer_tenure, peer_latency). It is computed from real libp2p
// connection data by HealthMonitor below, so a real running node can feed
// x/sovereignty's P2P sensor with real numbers instead of the mock values
// tests/e2e/ uses (see engram-sovereign-fsm's x/sovereignty/keeper/sensors/p2p_health.go).
//
// PeerLatencyMs is not yet populated (real RTT measurement, e.g. via
// go-libp2p's ping protocol, is future work) -- everything else is real.
type HealthSnapshot struct {
	SubnetDiversity uint64
	ActiveAnchors   uint64
	CleanPeers      uint64
	PeerChurnRate   uint64
	AvgPeerTenure   uint64
	PeerLatencyMs   uint64
}

// HealthMonitor tracks per-peer connection metadata (connect time, churn
// events) purely by observing PeerSet's existing Add/Remove lifecycle hooks
// (PeerAddOptions.OnAfterStart / PeerRemovalOptions.OnAfterStop) -- it does
// not modify PeerSet, Peer, or Switch, keeping this additive-only. Wiring
// OnPeerConnected/OnPeerDisconnected into Switch's PeerAddOptions/
// PeerRemovalOptions construction sites is the only integration point needed.
type HealthMonitor struct {
	mu sync.Mutex

	connectedSince map[peer.ID]time.Time
	churnEvents    []time.Time
	churnWindow    time.Duration

	anchorPeers    map[peer.ID]bool
	blacklistPeers map[peer.ID]bool
}

// NewHealthMonitor builds a HealthMonitor. anchorPeers mirrors the spec's
// notion of bootstrap/anchor peers (ActiveAnchors); churnWindow is the
// rolling window peer_churn_rate is counted over (spec's "per epoch").
func NewHealthMonitor(anchorPeers []peer.ID, churnWindow time.Duration) *HealthMonitor {
	anchors := make(map[peer.ID]bool, len(anchorPeers))
	for _, id := range anchorPeers {
		anchors[id] = true
	}
	return &HealthMonitor{
		connectedSince: make(map[peer.ID]time.Time),
		anchorPeers:    anchors,
		blacklistPeers: make(map[peer.ID]bool),
		churnWindow:    churnWindow,
	}
}

// OnPeerConnected should be included in every PeerAddOptions.OnAfterStart
// call site in switch.go (alongside the existing s.reactors.AddPeer hook).
func (h *HealthMonitor) OnPeerConnected(p *Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.connectedSince[p.AddrInfo().ID] = now
	h.churnEvents = append(h.churnEvents, now)
}

// OnPeerDisconnected should be included in PeerRemovalOptions.OnAfterStop
// (alongside the existing s.reactors.RemovePeer hook).
func (h *HealthMonitor) OnPeerDisconnected(p *Peer, _ any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.connectedSince, p.AddrInfo().ID)
	h.churnEvents = append(h.churnEvents, time.Now())
}

// Blacklist marks a peer as unclean (excluded from CleanPeers), mirroring
// spec's blacklisted_peers.
func (h *HealthMonitor) Blacklist(id peer.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.blacklistPeers[id] = true
}

// SetAnchorPeers replaces the anchor peer set wholesale -- this is the
// method NewSwitch's own doc comment promised ("anchor peers start empty
// and are configured via SetAnchorPeers once bootstrap peers are known")
// but that was never actually implemented, leaving ActiveAnchors
// permanently 0 regardless of real peer connectivity (Switch.OnStart's
// bootstrapPeers were computed but never fed here). Called once from
// Switch.OnStart with the resolved bootstrap/persistent peer set -- the
// same peers this repo's IsCriticalCondition (via engram-sovereign-fsm's
// spec/core/EngramFSM.tla-derived Cardinality(ActiveAnchors) = 0 check)
// needs to see at least one of connected to avoid an Eclipse-attack false
// positive.
func (h *HealthMonitor) SetAnchorPeers(ids []peer.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	anchors := make(map[peer.ID]bool, len(ids))
	for _, id := range ids {
		anchors[id] = true
	}
	h.anchorPeers = anchors
}

// Snapshot computes a HealthSnapshot from the currently-connected peer set
// (as returned by PeerSet.Copy()), mirroring ActiveAnchors/CleanPeers/
// SubnetDiversity's definitions (spec/core/EngramFSM.tla:66-73). Peers that
// aren't *lp2p.Peer (shouldn't happen in this codebase, but PeerSet.Copy()
// returns the p2p.Peer interface) are skipped defensively.
func (h *HealthMonitor) Snapshot(peers []p2p.Peer) HealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()

	subnets := make(map[string]bool)
	var activeAnchors, cleanPeers uint64
	var tenureSum time.Duration
	var tenureCount uint64

	now := time.Now()
	for _, raw := range peers {
		p, ok := raw.(*Peer)
		if !ok {
			continue
		}
		id := p.AddrInfo().ID

		if subnet := subnetOf(p); subnet != "" {
			subnets[subnet] = true
		}
		if h.anchorPeers[id] {
			activeAnchors++
		}
		if !h.blacklistPeers[id] {
			cleanPeers++
		}
		if since, ok := h.connectedSince[id]; ok {
			tenureSum += now.Sub(since)
			tenureCount++
		}
	}

	var avgTenure uint64
	if tenureCount > 0 {
		avgTenure = uint64((tenureSum / time.Duration(tenureCount)).Seconds())
	}

	return HealthSnapshot{
		SubnetDiversity: uint64(len(subnets)),
		ActiveAnchors:   activeAnchors,
		CleanPeers:      cleanPeers,
		PeerChurnRate:   h.pruneAndCountChurn(now),
		AvgPeerTenure:   avgTenure,
		PeerLatencyMs:   0,
	}
}

// pruneAndCountChurn drops churn events older than churnWindow and returns
// the count of events still within it. Caller must hold h.mu.
func (h *HealthMonitor) pruneAndCountChurn(now time.Time) uint64 {
	cutoff := now.Add(-h.churnWindow)
	kept := h.churnEvents[:0]
	for _, t := range h.churnEvents {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	h.churnEvents = kept
	return uint64(len(kept))
}

// subnetOf extracts a coarse /24 (IPv4) or /48 (IPv6) subnet identifier from
// a peer's socket address, for SubnetDiversity.
func subnetOf(p *Peer) string {
	na := p.SocketAddr()
	if na == nil || na.IP == nil {
		return ""
	}
	if v4 := na.IP.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return na.IP.Mask(net.CIDRMask(48, 128)).String()
}
