package propagator

import (
	"github.com/relab/hotstuff/core/eventloop"
	"github.com/relab/hotstuff/core/logging"
	"github.com/relab/hotstuff/protocol"
	"github.com/relab/hotstuff/protocol/votingmachine"
	"github.com/relab/hotstuff/security/blockchain"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/protocol/leaderrotation"
	"github.com/relab/hotstuff/security/cert"
)

type Propagator struct {
	config    *core.RuntimeConfig
	eventLoop *eventloop.EventLoop
	logger    logging.Logger

	leaderRotation leaderrotation.LeaderRotation
	blockchain     *blockchain.Blockchain
	viewStates     *protocol.ViewStates
	voteCollector  *VoteCollector

	seenMachine *votingmachine.SeenMachine

	sender core.Sender

	auth *cert.Authority
}

func NewPropagator(
	config *core.RuntimeConfig,
	eventLoop *eventloop.EventLoop,
	logger logging.Logger,

	leaderRotation leaderrotation.LeaderRotation,
	viewStates *protocol.ViewStates,
	auth *cert.Authority,
	voteCollector *VoteCollector,
	blockchain *blockchain.Blockchain,
	sender core.Sender,

	seenMachine *votingmachine.SeenMachine,
) *Propagator {
	p := &Propagator{
		config:    config,
		logger:    logger,
		eventLoop: eventLoop,

		leaderRotation: leaderRotation,
		viewStates:     viewStates,
		blockchain:     blockchain,
		voteCollector:  voteCollector,

		auth:   auth,
		sender: sender,

		seenMachine: seenMachine,
	}

	if config.HasNVC() {
		p.eventLoop.RegisterHandler(hotstuff.VoteMsg{}, func(event any) {
			p.OnVote(event.(hotstuff.VoteMsg))
		})
	}

	return p
}

// OnValidPropose is called when receiving a valid proposal from a leader and emits
// an event to advance the view. The proposal must be verified before calling this.
func (p *Propagator) OnVote(vote hotstuff.VoteMsg) {
	cert := vote.PartialCert
	p.logger.Debugf("OnVote(%d): %.8s", vote.ID, cert.BlockHash())

	var (
		block *hotstuff.Block
		ok    bool
	)

	if !vote.Deferred {
		block, ok = p.blockchain.LocalGet(cert.BlockHash())
		if !ok {
			p.logger.Debugf("Local cache miss for block: %.8s", cert.BlockHash())
			vote.Deferred = true
			p.eventLoop.DelayUntil(hotstuff.ProposeMsg{}, vote)
			return
		}
	} else {
		block, ok = p.blockchain.Get(cert.BlockHash())
		if !ok {
			p.logger.Debugf("Could not find block for vote: %.8s.", cert.BlockHash())
			return
		}
	}

	if block.View() <= p.viewStates.HighQSC().View() {
		// too old
		return
	}
	go p.verify(cert, block, vote.ID)
}

func (p *Propagator) verify(cert hotstuff.PartialCert, block *hotstuff.Block, voter hotstuff.ID) {
	if err := p.auth.VerifyPartialCert(cert); err != nil {
		p.logger.Infof("vote could not be verified: %v", err)
		return
	}

	spc, err := p.auth.CreateSeenPartialCert(cert.BlockHash(), voter)
	if err != nil {
		p.logger.Infof("OnVote: failed to sign vote: %v", err)
		return
	}

	voteSig := hotstuff.NewVoteSignature(cert.Signer(), cert.BlockHash(), cert.Signature())
	p.voteCollector.Add(voteSig, p.viewStates.View())

	leaderID := p.leaderRotation.GetLeader(block.View() + 1)
	if leaderID == p.config.ID() {
		p.seenMachine.CollectSeen(hotstuff.SeenMsg{
			ID:              leaderID,
			SeenPartialCert: spc,
		})
		p.logger.Debugf("[SendSeen] voterId=%d, hash=%s", voter, block.Hash())
		return
	}

	err = p.sender.SendSeen(leaderID, spc)
	if err != nil {
		p.logger.Warnf("Replica with ID %d was not found!", leaderID)
		return
	}
	p.logger.Debugf("[SendSeen] voterId=%d, hash=%s", voter, block.Hash())
}
