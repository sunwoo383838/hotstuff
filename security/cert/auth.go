// Package cert provides a certificate authority for creating and verifying quorum certificates.
package cert

import (
	"bytes"
	"fmt"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/security/blockchain"
	"github.com/relab/hotstuff/security/crypto"
)

type Authority struct {
	crypto.Base // embedded to avoid having to implement forwarding methods
	config      *core.RuntimeConfig
	blockchain  *blockchain.Blockchain
}

// NewAuthority returns an Authority. It will use the given CryptoBase to create and verify
// signatures.
func NewAuthority(
	config *core.RuntimeConfig,
	blockchain *blockchain.Blockchain,
	base crypto.Base,
	opts ...Option,
) *Authority {
	ca := &Authority{
		Base:       base,
		config:     config,
		blockchain: blockchain,
	}
	for _, opt := range opts {
		opt(ca)
	}
	return ca
}

// CreatePartialCert signs a single block and returns the partial certificate.
func (c *Authority) CreatePartialCert(block *hotstuff.Block) (cert hotstuff.PartialCert, err error) {
	sig, err := c.Sign(block.ToBytes())
	if err != nil {
		return hotstuff.PartialCert{}, err
	}
	return hotstuff.NewPartialCert(sig, block.Hash()), nil
}

// CreateQuorumCert creates a quorum certificate from a list of partial certificates.
func (c *Authority) CreateQuorumCert(block *hotstuff.Block, signatures []hotstuff.PartialCert) (cert hotstuff.QuorumCert, err error) {
	// genesis QC is always valid.
	if block.Hash() == hotstuff.GetGenesis().Hash() {
		return hotstuff.NewQuorumCert(nil, 0, hotstuff.GetGenesis().Hash()), nil
	}
	sigs := make([]hotstuff.QuorumSignature, 0, len(signatures))
	for _, sig := range signatures {
		sigs = append(sigs, sig.Signature())
	}
	sig, err := c.Combine(sigs...)
	if err != nil {
		return hotstuff.QuorumCert{}, err
	}
	return hotstuff.NewQuorumCert(sig, block.View(), block.Hash()), nil
}

// CreateTimeoutCert creates a timeout certificate from a list of timeout messages.
func (c *Authority) CreateTimeoutCert(view hotstuff.View, timeouts []hotstuff.TimeoutMsg) (cert hotstuff.TimeoutCert, err error) {
	// view 0 is always valid.
	if view == 0 {
		return hotstuff.NewTimeoutCert(nil, 0), nil
	}
	sigs := make([]hotstuff.QuorumSignature, 0, len(timeouts))
	for _, timeout := range timeouts {
		sigs = append(sigs, timeout.ViewSignature)
	}
	sig, err := c.Combine(sigs...)
	if err != nil {
		return hotstuff.TimeoutCert{}, err
	}
	return hotstuff.NewTimeoutCert(sig, view), nil
}

// CreateAggregateQC creates an AggregateQC from the given timeout messages.
func (c *Authority) CreateAggregateQC(view hotstuff.View, timeouts []hotstuff.TimeoutMsg) (aggQC hotstuff.AggregateQC, err error) {
	qcs := make(map[hotstuff.ID]hotstuff.QuorumCert)
	sigs := make([]hotstuff.QuorumSignature, 0, len(timeouts))
	for _, timeout := range timeouts {
		if qc, ok := timeout.SyncInfo.QC(); ok {
			qcs[timeout.ID] = qc
		}
		if timeout.MsgSignature != nil {
			sigs = append(sigs, timeout.MsgSignature)
		}
	}
	sig, err := c.Combine(sigs...)
	if err != nil {
		return hotstuff.AggregateQC{}, err
	}
	return hotstuff.NewAggregateQC(qcs, sig, view), nil
}

func (c *Authority) CreateQuorumSeenCert(block *hotstuff.Block, signatures []hotstuff.SeenCert) (cert hotstuff.QuorumSeenCert, err error) {
	if block.Hash() == hotstuff.GetGenesisQSC().Hash() {
		return hotstuff.NewQuorumSeenCert(nil, make(map[hotstuff.ID]hotstuff.IDSet), 0, hotstuff.GetGenesisQSC().Hash()), nil
	}
	metadata := make(map[hotstuff.ID]hotstuff.IDSet)
	sigs := make([]hotstuff.QuorumSignature, 0, len(signatures))
	for _, sig := range signatures {
		sigs = append(sigs, sig.Signature())
		participants := sig.Signature().Participants()
		participants.ForEach(func(id hotstuff.ID) {
			if _, ok := metadata[sig.Voter()]; !ok {
				metadata[sig.Voter()] = &crypto.Bitfield{}
			}
			metadata[sig.Voter()].Add(id)
		})
	}
	var base crypto.Base
	if unwrapper, ok := c.Base.(interface{ Unwrap() crypto.Base }); ok {
		base = unwrapper.Unwrap()
	}
	verifier, ok := base.(crypto.NVCVerifier)
	if !ok {
		return hotstuff.NewQuorumSeenCert(nil, make(map[hotstuff.ID]hotstuff.IDSet), 0, hotstuff.GetGenesisQSC().Hash()),
			fmt.Errorf("verifer error")
	}
	qsc, err := verifier.SeenCertCombine(sigs...)
	if err != nil {
		return hotstuff.QuorumSeenCert{}, err
	}
	return hotstuff.NewQuorumSeenCert(qsc, metadata, block.View(), block.Hash()), nil
}

// VerifyPartialCert verifies a single partial certificate.
func (c *Authority) VerifyPartialCert(cert hotstuff.PartialCert) error {
	block, ok := c.blockchain.Get(cert.BlockHash())
	if !ok {
		return fmt.Errorf("block not found: %v", cert.BlockHash())
	}
	return c.Verify(cert.Signature(), block.ToBytes())
}

// VerifyQuorumCert verifies a quorum certificate.
func (c *Authority) VerifyQuorumCert(qc hotstuff.QuorumCert) error {
	// genesis QC is always valid.
	if qc.BlockHash() == hotstuff.GetGenesis().Hash() {
		return nil
	}

	// TODO: FIX BUG - qcSignature can be nil when a leader is byzantine.
	qcSignature := qc.Signature()
	if qcSignature == nil {
		return fmt.Errorf("quorum certificate has nil signature (view=%d)", qc.View())
	}

	participants := qcSignature.Participants()
	quorumSize := c.config.QuorumSize()
	if participants.Len() < quorumSize {
		return fmt.Errorf("%d participants cannot satisfy the quorum requirement: %d", participants.Len(), quorumSize)
	}
	block, ok := c.blockchain.Get(qc.BlockHash())
	if !ok {
		return fmt.Errorf("block not found: %v", qc.BlockHash())
	}
	return c.Verify(qc.Signature(), block.ToBytes())
}

// VerifyTimeoutCert verifies a timeout certificate.
func (c *Authority) VerifyTimeoutCert(tc hotstuff.TimeoutCert) error {
	// view 0 TC is always valid.
	if tc.View() == 0 {
		return nil
	}
	quorumSize := c.config.QuorumSize()
	participants := tc.Signature().Participants()
	if participants.Len() < quorumSize {
		return fmt.Errorf("%d participants cannot satisfy the quorum requirement: %d", participants.Len(), quorumSize)
	}
	return c.Verify(tc.Signature(), tc.View().ToBytes())
}

// VerifyAggregateQC verifies the AggregateQC and returns the highQC, if valid.
func (c *Authority) VerifyAggregateQC(aggQC hotstuff.AggregateQC) (highQC hotstuff.QuorumCert, err error) {
	messages := make(map[hotstuff.ID][]byte)
	for id, qc := range aggQC.QCs() {
		if highQC.View() < qc.View() || highQC == (hotstuff.QuorumCert{}) {
			highQC = qc
		}
		// reconstruct the TimeoutMsg to get the hash
		messages[id] = hotstuff.TimeoutMsg{
			ID:       id,
			View:     aggQC.View(),
			SyncInfo: hotstuff.NewSyncInfo().WithQC(qc),
		}.ToBytes()
	}
	quorumSize := c.config.QuorumSize()
	participants := aggQC.Sig().Participants()
	if participants.Len() < quorumSize {
		return hotstuff.QuorumCert{}, fmt.Errorf("%d participants cannot satisfy the quorum requirement: %d", participants.Len(), quorumSize)
	}
	// both the batched aggQC signatures and the highQC must be verified
	if err := c.BatchVerify(aggQC.Sig(), messages); err != nil {
		return hotstuff.QuorumCert{}, err
	}

	if err := c.VerifyQuorumCert(highQC); err != nil {
		return hotstuff.QuorumCert{}, err
	}
	return highQC, nil
}

func (c *Authority) VerifyNewViewCert(nvc hotstuff.NewViewCert) (sig hotstuff.QuorumSignature, highQSC hotstuff.QuorumSeenCert, err error) {
	if nvc.Sig() == nil {
		return nil, hotstuff.QuorumSeenCert{}, fmt.Errorf("signature is nil")
	}
	messages := make(map[hotstuff.ID]hotstuff.TimeoutMsg)
	messagesBytes := make(map[hotstuff.ID][]byte)
	voteSigs := make(map[hotstuff.Hash]map[hotstuff.ID]hotstuff.QuorumSignature)
	var anchor hotstuff.Hash
	var voteSig hotstuff.QuorumSignature

	for id, qsc := range nvc.QSCs() {
		if highQSC.View() < qsc.View() || highQSC.Equals(hotstuff.QuorumSeenCert{}) {
			highQSC = qsc
		}

		messages[id] = hotstuff.TimeoutMsg{
			ID:       id,
			View:     nvc.View(),
			SyncInfo: hotstuff.NewSyncInfo().WithQSC(qsc),
			Votes:    hotstuff.NewVoteSignatureSet(),
		}
	}

	for vs, idSet := range nvc.VoteSigs() {
		idSet.ForEach(func(id hotstuff.ID) {
			msg := messages[id]
			msg.Votes.Add(vs)
			messages[id] = msg
		})
	}

	for id, msg := range messages {
		messagesBytes[id] = msg.ToBytes()
		if qsc, ok := msg.SyncInfo.QSC(); ok {
			if qsc.View() == highQSC.View() {
				msg.Votes.ForEach(func(vote hotstuff.VoteSignature) {
					if _, ok := voteSigs[vote.Hash()]; !ok {
						voteSigs[vote.Hash()] = make(map[hotstuff.ID]hotstuff.QuorumSignature)
					}
					voteSigs[vote.Hash()][vote.Id()] = vote.Signature()
				})
			}
		}
	}

	quorumSize := c.config.QuorumSize()
	if nvc.Sig().Participants().Len() < quorumSize {
		return nil, hotstuff.QuorumSeenCert{},
			fmt.Errorf("quorumsize")
	}
	if err := c.BatchVerify(nvc.Sig(), messagesBytes); err != nil {
		if err = c.VerifyQuorumSeenCert(highQSC); err != nil {
			return nil, hotstuff.QuorumSeenCert{}, err
		}
	}

	for hash, inner := range voteSigs {
		if len(inner) >= quorumSize {
			sigs := make([]hotstuff.QuorumSignature, 0)
			for _, sig := range inner {
				sigs = append(sigs, sig)
			}
			if agg, _, ok := c.DCPickQuorum(hash[:], sigs, quorumSize); ok {
				voteSig = agg
				anchor = hash
				break
			}
		}
	}

	if nvc.VoteSig() == nil {
		if voteSig == nil && highQSC.BlockHash() == nvc.Anchor() {
			return voteSig, highQSC, nil
		} else {
			return voteSig, highQSC, fmt.Errorf("정보불일치")
		}
	} else {
		if voteSig != nil &&
			bytes.Equal(nvc.VoteSig().ToBytes(), voteSig.ToBytes()) && anchor == nvc.Anchor() {
			return voteSig, highQSC, nil
		} else {
			return voteSig, highQSC, fmt.Errorf("정보불일치")
		}
	}

}

func (c *Authority) CreateNewViewCert(view hotstuff.View, timeouts []hotstuff.TimeoutMsg, highQSC hotstuff.QuorumSeenCert) (nvc hotstuff.NewViewCert, err error) {
	qscs := make(map[hotstuff.ID]hotstuff.QuorumSeenCert)
	sigs := make([]hotstuff.QuorumSignature, 0, len(timeouts))
	voteSigs := make(map[hotstuff.Hash]map[hotstuff.ID]hotstuff.QuorumSignature)
	idSetByVoteSig := make(map[hotstuff.VoteSignature]hotstuff.IDSet)
	var anchor hotstuff.Hash
	var voteSig hotstuff.QuorumSignature

	for _, timeout := range timeouts {
		if qsc, ok := timeout.SyncInfo.QSC(); ok {
			qscs[timeout.ID] = qsc
			if timeout.Votes != nil {
				for _, voteSig := range timeout.Votes.ToSlice() {
					if _, ok := voteSigs[voteSig.Hash()]; !ok {
						voteSigs[voteSig.Hash()] = make(map[hotstuff.ID]hotstuff.QuorumSignature)
					}
					if block, ok := c.blockchain.LocalGet(voteSig.Hash()); ok {
						if block.Parent() == highQSC.BlockHash() {
							voteSigs[voteSig.Hash()][voteSig.Id()] = voteSig.Signature()
						}
					} else {
						voteSigs[voteSig.Hash()][voteSig.Id()] = voteSig.Signature()
					}
					if _, exists := idSetByVoteSig[voteSig]; !exists {
						idSetByVoteSig[voteSig] = &crypto.Bitfield{}
					}
					idSetByVoteSig[voteSig].Add(timeout.ID)
				}
			}
		}
		if timeout.MsgSignature != nil {
			sigs = append(sigs, timeout.MsgSignature)
		}
	}

	quorumSize := c.config.QuorumSize()
	for hash, inner := range voteSigs {
		if len(inner) >= quorumSize {
			sigs := make([]hotstuff.QuorumSignature, 0)
			for _, sig := range inner {
				sigs = append(sigs, sig)
			}
			if agg, _, ok := c.DCPickQuorum(hash[:], sigs, quorumSize); ok {
				voteSig = agg
				anchor = hash
				break
			}
		}
	}
	msgSig, err := c.Combine(sigs...)
	if err != nil {
		return hotstuff.NewViewCert{}, err
	}
	if voteSig == nil {
		anchor = highQSC.BlockHash()
		return hotstuff.NewNewViewCert(qscs, msgSig, nil, anchor, view, idSetByVoteSig), nil
	}

	return hotstuff.NewNewViewCert(qscs, msgSig, voteSig, anchor, view, idSetByVoteSig), nil
}

func (c *Authority) CreateSeenPartialCert(hash hotstuff.Hash, voter hotstuff.ID) (cert hotstuff.SeenPartialCert, err error) {
	sig, err := c.Sign(append(hash[:], voter.ToBytes()...))
	if err != nil {
		return hotstuff.SeenPartialCert{}, err
	}
	return hotstuff.NewSeenPartialCert(sig, hash, voter), nil
}

func (c *Authority) CreateSeenCert(hash hotstuff.Hash, voter hotstuff.ID, signatures []hotstuff.SeenPartialCert) (cert hotstuff.SeenCert, err error) {
	sigs := make([]hotstuff.QuorumSignature, 0, len(signatures))
	for _, sig := range signatures {
		sigs = append(sigs, sig.Signature())
	}
	sig, err := c.Combine(sigs...)
	if err != nil {
		return hotstuff.SeenCert{}, err
	}
	return hotstuff.NewSeenCert(sig, hash, voter), nil
}

func (c *Authority) VerifyQuorumSeenCert(qsc hotstuff.QuorumSeenCert) error {
	if qsc.BlockHash() == hotstuff.GetGenesisQSC().Hash() {
		return nil
	}
	var base crypto.Base
	if unwrapper, ok := c.Base.(interface{ Unwrap() crypto.Base }); ok {
		base = unwrapper.Unwrap()
	}
	verifier, ok := base.(crypto.NVCVerifier)
	if !ok {
		return fmt.Errorf("verifer error")
	}
	return verifier.VerifyQuorumSeenCert(&qsc)
}

func (c *Authority) VerifyAndCreateSeenCert(certs []hotstuff.SeenPartialCert) (sc hotstuff.SeenCert, ok bool) {
	if len(certs) == 0 {
		return
	}
	seenDigest := certs[0].ToBytes()

	sigs := make([]hotstuff.QuorumSignature, len(certs))
	for i := range certs {
		sigs[i] = certs[i].Signature()
	}

	sig, mask, _ := c.DCAggOrMask(seenDigest[:], sigs)
	if sig != nil {
		return hotstuff.NewSeenCert(sig, certs[0].BlockHash(), certs[0].Voter()), true
	}

	for i, ok := range mask {
		certs[i].SetVerified(ok)
	}
	return hotstuff.SeenCert{}, false
}

func (c *Authority) DCAggOrMask(msg []byte, sigs []hotstuff.QuorumSignature) (sig hotstuff.QuorumSignature, mask []bool, validCount int) {
	n := len(sigs)
	if n == 0 {
		return nil, nil, 0
	}

	if full, err := c.Combine(sigs...); err == nil {
		if err = c.Verify(full, msg); err == nil {
			return full, nil, n
		}
	}

	mask = make([]bool, n)
	type seg struct{ lo, hi int }
	stack := []seg{{0, n}}
	validCount = 0

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if s.lo >= s.hi {
			continue
		}
		m := s.hi - s.lo

		if m == 1 {
			if err := c.Verify(sigs[s.lo], msg); err == nil {
				if !mask[s.lo] {
					mask[s.lo] = true
					validCount++
				}
			}
			continue
		}

		if part, err := c.Combine(sigs[s.lo:s.hi]...); err == nil {
			if err = c.Verify(part, msg); err == nil {
				for i := s.lo; i < s.hi; i++ {
					if !mask[i] {
						mask[i] = true
						validCount++
					}
				}
				continue
			}
		}

		mid := s.lo + m/2
		stack = append(stack, seg{s.lo, mid}, seg{mid, s.hi})
	}

	return nil, mask, validCount
}

func (c *Authority) DCPickQuorum(msg []byte, sigs []hotstuff.QuorumSignature, quorum int) (agg hotstuff.QuorumSignature, mask []bool, ok bool) {
	if len(sigs) < quorum {
		return nil, nil, false
	}

	sig, mask, cnt := c.DCAggOrMask(msg, sigs)
	if sig != nil {
		return sig, mask, true
	}

	if cnt < quorum {
		return nil, mask, false
	}

	acc := make([]hotstuff.QuorumSignature, 0, cnt)
	for i, good := range mask {
		if good {
			acc = append(acc, sigs[i])
		}
	}

	aggSig, err := c.Combine(acc...)
	if err != nil {
		return nil, mask, false
	}
	if err = c.Verify(aggSig, msg); err == nil {
		return nil, mask, false
	}
	return aggSig, mask, true
}

// VerifyAnyQC is a helper that verifies either a QC or the aggregateQC in a proposal message.
func (c *Authority) VerifyAnyQC(proposal *hotstuff.ProposeMsg) (err error, commit bool) {
	if c.config.HasNVC() {
		qsc := proposal.Block.QuorumSeenCert()
		nvc := proposal.NVC
		if nvc != nil {
			voteSig, highQSC, err := c.VerifyNewViewCert(*nvc)
			if err != nil {
				return err, false
			}
			if !qsc.Equals(highQSC) {
				return fmt.Errorf("highQSC가 맞지않음"), false
			}

			if voteSig != nil {
				return nil, true
			}
		} else {
			return c.VerifyQuorumSeenCert(qsc), false
		}
	}
	qc := proposal.Block.QuorumCert()
	aggQC := proposal.AggregateQC
	if c.config.HasAggregateQC() && aggQC != nil {
		highQC, err := c.VerifyAggregateQC(*aggQC)
		if err != nil {
			return err, false
		}
		// for simplicity, we require that the highQC found in the AggregateQC equals the block's QC.
		if !qc.Equals(highQC) {
			return fmt.Errorf("block QC does not match the highQC of the block's aggregate QC"), false
		}
	}
	return c.VerifyQuorumCert(qc), false
}
