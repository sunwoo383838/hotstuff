package synchronizer

import (
	"fmt"
	"github.com/relab/hotstuff/protocol"
	"github.com/relab/hotstuff/protocol/propagator"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/security/cert"
)

// Aggregate implements an aggregate timeout rule.
type NVC struct {
	config        *core.RuntimeConfig
	auth          *cert.Authority
	voteCollector *propagator.VoteCollector
	viewStates    *protocol.ViewStates
}

// NewAggregate returns an aggregate timeout rule instance.
func NewNVC(
	config *core.RuntimeConfig,
	auth *cert.Authority,
	voteCollector *propagator.VoteCollector,
	viewStates *protocol.ViewStates,
) *NVC {
	return &NVC{
		config:        config,
		auth:          auth,
		voteCollector: voteCollector,
		viewStates:    viewStates,
	}
}

func (n *NVC) LocalTimeoutRule(view hotstuff.View, syncInfo hotstuff.SyncInfo) (*hotstuff.TimeoutMsg, error) {
	sig, err := n.auth.Sign(view.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign view %d: %w", view, err)
	}
	sigSet := hotstuff.NewVoteSignatureSet()
	for _, vs := range n.voteCollector.Get(view) {
		sigSet.Add(vs)
	}
	timeoutMsg := &hotstuff.TimeoutMsg{
		ID:            n.config.ID(),
		View:          view,
		SyncInfo:      syncInfo,
		ViewSignature: sig,
		Votes:         sigSet,
	}

	// generate a second signature that will become part of the aggregateQC
	sig, err = n.auth.Sign(timeoutMsg.ToBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign timeout message: %w", err)
	}
	timeoutMsg.MsgSignature = sig

	return timeoutMsg, nil
}

func (s *NVC) RemoteTimeoutRule(currentView, timeoutView hotstuff.View, timeouts []hotstuff.TimeoutMsg) (hotstuff.SyncInfo, error) {
	nvc, err := s.auth.CreateNewViewCert(currentView, timeouts, s.viewStates.HighQSC())
	if err != nil {
		return hotstuff.SyncInfo{}, fmt.Errorf("failed to new view certificate: %w", err)
	}
	return hotstuff.NewSyncInfo().WithNVC(nvc), nil
}

func (s *NVC) VerifySyncInfo(syncInfo hotstuff.SyncInfo) (qsc hotstuff.Cert, view hotstuff.View, timeout bool, err error) {
	if nvc, haveQSC := syncInfo.NVC(); haveQSC {
		_, highQSC, err := s.auth.VerifyNewViewCert(nvc)
		if err != nil {
			return nil, 0, timeout, fmt.Errorf("failed to verify new view certificate: %w", err)
		}
		if nvc.View() >= view {
			view = nvc.View()
			timeout = true
		}
		var cert hotstuff.Cert = highQSC
		return cert, view, timeout, nil
	} else if quorumSeenCert, haveQSC := syncInfo.QSC(); haveQSC {
		if err := s.auth.VerifyQuorumSeenCert(quorumSeenCert); err != nil {
			return nil, 0, timeout, fmt.Errorf("failed to verify quorum seen certificate: %w", err)
		}
		// if there is both a TC and a QC, we use the QC if its view is greater or equal to the TC.
		if quorumSeenCert.View() >= view {
			view = quorumSeenCert.View()
			timeout = false
		}
		return quorumSeenCert, view, timeout, nil
	}
	return nil, view, timeout, nil // aggregate quorum certificate not present, so no high QC available
}
