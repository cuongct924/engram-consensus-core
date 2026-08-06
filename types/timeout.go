package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// Timeout is a validator's signed attestation that its local round timer
// expired for (Height, Round) -- backs f+1-quorum round-skip
// (engram-sovereign-fsm's M0b, mirrors spec/core/EngramTendermint.tla's
// BroadcastTimeout/UponfPlusOneTimeoutsAny) instead of a purely
// local-timer-driven round advance. See proto/tendermint/types/types.proto's
// Timeout message doc for why it skips Vote's HRS double-sign protection.
type Timeout struct {
	Height           int64
	Round            int32
	ValidatorAddress crypto.Address
	ValidatorIndex   int32
	Signature        []byte
}

// ToProto converts Timeout to protobuf.
func (t *Timeout) ToProto() *cmtproto.Timeout {
	if t == nil {
		return nil
	}
	return &cmtproto.Timeout{
		Height:           t.Height,
		Round:            t.Round,
		ValidatorAddress: t.ValidatorAddress,
		ValidatorIndex:   t.ValidatorIndex,
		Signature:        t.Signature,
	}
}

// TimeoutFromProto converts a protobuf Timeout back into a domain Timeout.
func TimeoutFromProto(pb *cmtproto.Timeout) (*Timeout, error) {
	if pb == nil {
		return nil, errors.New("nil timeout")
	}
	return &Timeout{
		Height:           pb.Height,
		Round:            pb.Round,
		ValidatorAddress: pb.ValidatorAddress,
		ValidatorIndex:   pb.ValidatorIndex,
		Signature:        pb.Signature,
	}, nil
}

// TimeoutSignBytes returns the bytes a validator signs to attest to a
// timeout at (height, round) on chainID. Deliberately simpler than
// VoteSignBytes/ProposalSignBytes's CanonicalVote/CanonicalProposal +
// sfixed64 amino-style encoding (needed there for cross-implementation/
// hardware-wallet determinism): a Timeout is not a slashable,
// equivocation-sensitive message the way a double-voted block is, so a
// plain fixed-width concatenation of (height, round, chainID) is a
// sufficient, unambiguous, deterministic encoding for this fork's purposes.
func TimeoutSignBytes(chainID string, height int64, round int32) []byte {
	buf := make([]byte, 0, 8+4+len(chainID))
	buf = binary.BigEndian.AppendUint64(buf, uint64(height))
	buf = binary.BigEndian.AppendUint32(buf, uint32(round))
	buf = append(buf, []byte(chainID)...)
	return buf
}

// ValidateBasic performs basic validation.
func (t *Timeout) ValidateBasic() error {
	if t.Height < 0 {
		return errors.New("negative Height")
	}
	if t.Round < 0 {
		return errors.New("negative Round")
	}
	if len(t.ValidatorAddress) != crypto.AddressSize {
		return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize, len(t.ValidatorAddress))
	}
	if t.ValidatorIndex < 0 {
		return errors.New("negative ValidatorIndex")
	}
	if len(t.Signature) == 0 {
		return errors.New("signature is missing")
	}
	if len(t.Signature) > MaxSignatureSize {
		return fmt.Errorf("signature is too big (max: %d)", MaxSignatureSize)
	}
	return nil
}

// Verify checks Signature against pubKey over TimeoutSignBytes(chainID, ...),
// and that pubKey's address matches ValidatorAddress.
func (t *Timeout) Verify(chainID string, pubKey crypto.PubKey) error {
	if !bytes.Equal(pubKey.Address(), t.ValidatorAddress) {
		return errors.New("invalid validator address")
	}
	if !pubKey.VerifySignature(TimeoutSignBytes(chainID, t.Height, t.Round), t.Signature) {
		return errors.New("invalid timeout signature")
	}
	return nil
}

func (t *Timeout) String() string {
	if t == nil {
		return "nil-Timeout"
	}
	return fmt.Sprintf("Timeout{%v/%02d %X}", t.Height, t.Round, t.ValidatorAddress)
}
