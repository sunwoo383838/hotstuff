package rules

import (
	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/core/logging"
	"github.com/relab/hotstuff/internal/proto/clientpb"
	"github.com/relab/hotstuff/protocol/consensus"
	"github.com/relab/hotstuff/security/blockchain"
)

const NameHotStuff1 = "hotstuff1"

// FastHotStuff is an implementation of the Fast-HotStuff protocol.
type HotStuff1 struct {
	logger     logging.Logger
	config     *core.RuntimeConfig
	blockchain *blockchain.Blockchain
}

// NewFastHotStuff returns a new instance of the Fast-HotStuff consensus ruleset.
func NewHotStuff1(
	logger logging.Logger,
	config *core.RuntimeConfig,
	blockchain *blockchain.Blockchain,
) *HotStuff1 {
	if !config.HasNVC() {
		panic("aggregate qc must be enabled for fasthotstuff")
	}
	return &HotStuff1{
		logger:     logger,
		config:     config,
		blockchain: blockchain,
	}
}

func (h1 *HotStuff1) qscRef(qsc hotstuff.QuorumSeenCert) (*hotstuff.Block, bool) {
	if (hotstuff.Hash{}) == qsc.BlockHash() {
		return nil, false
	}
	return h1.blockchain.Get(qsc.BlockHash())
}

// CommitRule decides whether an ancestor of the block can be committed.
func (h1 *HotStuff1) CommitRule(block *hotstuff.Block) *hotstuff.Block {
	parent, ok := h1.qscRef(block.QuorumSeenCert())
	if !ok {
		return nil
	}
	if block.Parent() == parent.Hash() && block.View() == parent.View()+1 {
		h1.logger.Debug("COMMIT: ", parent)
		return parent
	}
	return nil
}

// VoteRule decides whether to vote for the proposal or not.
func (h1 *HotStuff1) VoteRule(view hotstuff.View, proposal hotstuff.ProposeMsg) bool {
	if proposal.NVC != nil {
		hqscBlock, ok := h1.blockchain.Get(proposal.Block.QuorumSeenCert().BlockHash())
		return ok && h1.blockchain.Extends(proposal.Block, hqscBlock)
	}
	return proposal.Block.View() >= view &&
		proposal.Block.View() == proposal.Block.QuorumSeenCert().View()+1
}

// ChainLength returns the number of blocks that need to be chained together in order to commit.
func (fhs *HotStuff1) ChainLength() int {
	return 1
}

// ProposeRule returns a new fast hotstuff proposal based on the current view, (aggregate) quorum certificate, and command batch.
func (fhs *HotStuff1) ProposeRule(view hotstuff.View, _ hotstuff.Cert, cert hotstuff.SyncInfo, cmd *clientpb.Batch) (proposal hotstuff.ProposeMsg, ok bool) {
	qsc, _ := cert.QSC() // TODO: we should avoid cert does not contain a QC so we cannot fail here
	proposal = hotstuff.NewProposeMsg(fhs.config.ID(), view, qsc, cmd)
	if nvc, ok := cert.NVC(); ok {
		proposal.NVC = &nvc
	}
	return proposal, true
}

var _ consensus.Ruleset = (*HotStuff1)(nil)
