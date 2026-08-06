package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/p2p"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// signTimeoutFrom builds and signs a Timeout attestation as if it came from
// validator vs, simulating a peer-broadcast TimeoutMessage for M0b's
// f+1-quorum round-skip tests below.
func signTimeoutFrom(t *testing.T, vs *validatorStub, chainID string, height int64, round int32) *types.Timeout {
	t.Helper()
	pubKey, err := vs.GetPubKey()
	require.NoError(t, err)

	pb := &cmtproto.Timeout{
		Height:           height,
		Round:            round,
		ValidatorAddress: pubKey.Address(),
		ValidatorIndex:   vs.Index,
	}
	require.NoError(t, vs.SignTimeout(chainID, pb))

	timeout, err := types.TimeoutFromProto(pb)
	require.NoError(t, err)
	return timeout
}

// TestStateRoundSkipFPlus1Quorum simulates a stalled leader (cs1 receives no
// votes at all, so it can never reach RoundStepPrecommitWait/Fallback on its
// own -- HasTwoThirdsAny needs 3 of 4 validators) and confirms the ONLY way
// cs1's round can advance is via the f+1-quorum TimeoutMessage mechanism:
// fewer than f+1 distinct validator signers must NOT trigger a round-skip,
// and reaching exactly f+1 must trigger one immediately, without waiting for
// the bounded fallback timer (RoundStepPrecommitWaitFallback).
func TestStateRoundSkipFPlus1Quorum(t *testing.T) {
	cs1, vss := randState(4) // N=4 -> f=1, threshold1=f+1=2
	height, round := cs1.Height, cs1.Round
	chainID := cs1.state.ChainID

	newRoundCh := subscribe(cs1.eventBus, types.EventQueryNewRound)

	startTestRound(cs1, height, round)
	ensureNewRound(newRoundCh, height, round)

	targetRound := round + 1

	// Only 1 of the 2 required distinct signers -- must NOT round-skip.
	t1 := signTimeoutFrom(t, vss[1], chainID, height, targetRound)
	cs1.peerMsgQueue <- msgInfo{&TimeoutMessage{Timeout: t1}, p2p.ID("peer1")}
	ensureNoNewEvent(newRoundCh, ensureTimeout,
		"must not round-skip with only 1 of 2 required timeout signers")
	require.Equal(t, round, cs1.GetRoundState().Round, "round must not have advanced")

	// A second, distinct validator signer reaches f+1=2 -- must round-skip
	// immediately.
	t2 := signTimeoutFrom(t, vss[2], chainID, height, targetRound)
	cs1.peerMsgQueue <- msgInfo{&TimeoutMessage{Timeout: t2}, p2p.ID("peer2")}
	ensureNewRound(newRoundCh, height, targetRound)
	require.Equal(t, targetRound, cs1.GetRoundState().Round,
		"round must have fast-forwarded to targetRound once f+1 quorum was reached")
}

// TestStateRoundSkipRejectsUnauthenticatedSender confirms the M0b auth fix:
// a Timeout claiming to be from a validator address but signed by a
// DIFFERENT (non-validator) key must be dropped, not counted toward quorum.
// Without this check, any connected peer -- not necessarily a validator --
// could impersonate distinct validator addresses and forge an f+1 quorum
// without controlling any real validator stake (see
// recordTimeoutSenderAndMaybeAdvance's doc in state.go).
func TestStateRoundSkipRejectsUnauthenticatedSender(t *testing.T) {
	cs1, vss := randState(4) // N=4 -> f=1, threshold1=f+1=2
	height, round := cs1.Height, cs1.Round
	chainID := cs1.state.ChainID

	newRoundCh := subscribe(cs1.eventBus, types.EventQueryNewRound)

	startTestRound(cs1, height, round)
	ensureNewRound(newRoundCh, height, round)

	targetRound := round + 1

	// A genuine signer from vss[1] -- 1 of 2 required.
	t1 := signTimeoutFrom(t, vss[1], chainID, height, targetRound)
	cs1.peerMsgQueue <- msgInfo{&TimeoutMessage{Timeout: t1}, p2p.ID("peer1")}
	ensureNoNewEvent(newRoundCh, ensureTimeout, "must not round-skip yet")

	// An outsider key (not in cs1.Validators) signs a Timeout claiming to be
	// vss[2] -- an impersonation/forgery attempt, not a second real signer.
	outsider := types.NewMockPV()
	vs2PubKey, err := vss[2].GetPubKey()
	require.NoError(t, err)
	forged := &cmtproto.Timeout{
		Height:           height,
		Round:            targetRound,
		ValidatorAddress: vs2PubKey.Address(),
		ValidatorIndex:   vss[2].Index,
	}
	require.NoError(t, outsider.SignTimeout(chainID, forged))
	forgedTimeout, err := types.TimeoutFromProto(forged)
	require.NoError(t, err)

	cs1.peerMsgQueue <- msgInfo{&TimeoutMessage{Timeout: forgedTimeout}, p2p.ID("attacker")}
	ensureNoNewEvent(newRoundCh, ensureTimeout,
		"a forged/unauthenticated timeout must not be counted toward quorum")
	require.Equal(t, round, cs1.GetRoundState().Round, "round must not have advanced")

	// A genuine second signer (vss[2] itself) now legitimately reaches
	// f+1=2 -- confirms the earlier forged message truly wasn't silently
	// counted (otherwise this one would be redundant / already have
	// advanced above).
	t2 := signTimeoutFrom(t, vss[2], chainID, height, targetRound)
	cs1.peerMsgQueue <- msgInfo{&TimeoutMessage{Timeout: t2}, p2p.ID("peer2")}
	ensureNewRound(newRoundCh, height, targetRound)
	require.Equal(t, targetRound, cs1.GetRoundState().Round)
}
