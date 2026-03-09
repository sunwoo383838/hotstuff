// Package protocol maintains the protocol's view states, which include
// the high quorum certificate (HighQC), high timeout certificate (HighTC),
// the current view, and the last committed block.
package protocol

import (
	"fmt"
	"github.com/relab/hotstuff/core"
	"sync"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/security/blockchain"
	"github.com/relab/hotstuff/security/cert"
)

// ViewStates is a shared object which stores the protocol's state and may be modified
// by several consensus component objects.
type ViewStates struct {
	blockchain *blockchain.Blockchain
	auth       *cert.Authority
	config     *core.RuntimeConfig

	mut sync.RWMutex // to protect the following

	highTC         hotstuff.TimeoutCert
	highQC         hotstuff.QuorumCert
	highQSC        hotstuff.QuorumSeenCert
	view           hotstuff.View
	committedBlock *hotstuff.Block
}

func NewViewStates(
	blockchain *blockchain.Blockchain,
	auth *cert.Authority,
	config *core.RuntimeConfig,
) (*ViewStates, error) {
	s := &ViewStates{
		blockchain: blockchain,
		auth:       auth,
		config:     config,

		view: 1,
	}
	var err error
	if config.HasNVC() {
		s.committedBlock = hotstuff.GetGenesisQSC()
		s.highQSC, err = s.auth.CreateQuorumSeenCert(hotstuff.GetGenesisQSC(), []hotstuff.SeenCert{})
		if err != nil {
			return nil, fmt.Errorf("unable to create empty quorum seen cert for genesis block: %v", err)
		}
		return s, nil
	}
	s.committedBlock = hotstuff.GetGenesis()
	s.highQC, err = s.auth.CreateQuorumCert(hotstuff.GetGenesis(), []hotstuff.PartialCert{})
	if err != nil {
		return nil, fmt.Errorf("unable to create empty quorum cert for genesis block: %v", err)
	}
	s.highTC, err = s.auth.CreateTimeoutCert(hotstuff.View(0), []hotstuff.TimeoutMsg{})
	if err != nil {
		return nil, fmt.Errorf("unable to create empty timeout cert for view 0: %v", err)
	}

	return s, nil
}

// UpdateHighQC updates HighQC if quorum certificate's block is for a higher view.
// It returns true if HighQC was updated. It returns an error if the
// quorum certificate's block is not found in the local blockchain.
func (s *ViewStates) UpdateHighQC(qc hotstuff.QuorumCert) (bool, error) {
	newBlock, ok := s.blockchain.Get(qc.BlockHash())
	if !ok {
		return false, fmt.Errorf("block %x not found for QC@view %d", qc.BlockHash(), qc.View())
	}
	s.mut.Lock()
	defer s.mut.Unlock()
	if newBlock.View() <= s.highQC.View() {
		return false, nil
	}
	s.highQC = qc
	return true, nil
}

func (s *ViewStates) UpdateHighQSC(qsc hotstuff.QuorumSeenCert) (bool, error) {
	newBlock, ok := s.blockchain.Get(qsc.BlockHash())
	if !ok {
		return false, fmt.Errorf("block %x not found for QSC@view %d", qsc.BlockHash(), qsc.View())
	}
	s.mut.Lock()
	defer s.mut.Unlock()
	if newBlock.View() <= s.highQSC.View() {
		return false, nil
	}
	s.highQSC = qsc
	return true, nil
}

// UpdateHighTC updates HighTC if timeout certificate's view is higher than the current HighTC.
func (s *ViewStates) UpdateHighTC(tc hotstuff.TimeoutCert) {
	if tc.View() > s.highTC.View() {
		s.highTC = tc
	}
}

// HighQC returns the highest known quorum certificate.
func (s *ViewStates) HighQC() hotstuff.QuorumCert {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.highQC
}

// HighQC returns the highest known quorum certificate.
func (s *ViewStates) HighQSC() hotstuff.QuorumSeenCert {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.highQSC
}

// HighTC returns the highest known timeout certificate.
func (s *ViewStates) HighTC() hotstuff.TimeoutCert {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.highTC
}

// NextView increments the current view and returns the new view.
func (s *ViewStates) NextView() hotstuff.View {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.view++
	return s.view
}

// View returns the current view.
func (s *ViewStates) View() hotstuff.View {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.view
}

// SyncInfo returns the highest known QC or TC.
func (s *ViewStates) SyncInfo() hotstuff.SyncInfo {
	s.mut.RLock()
	defer s.mut.RUnlock()
	if s.config.HasNVC() {
		return hotstuff.NewSyncInfo().WithQSC(s.HighQSC())
	}
	return hotstuff.NewSyncInfo().WithQC(s.HighQC()).WithTC(s.HighTC())
}

// UpdateCommittedBlock updates the last committed block.
func (s *ViewStates) UpdateCommittedBlock(block *hotstuff.Block) {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.committedBlock = block
}

// CommittedBlock retrieves the last block which was committed.
func (s *ViewStates) CommittedBlock() *hotstuff.Block {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.committedBlock
}
