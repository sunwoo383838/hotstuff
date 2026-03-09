package comm

import (
	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/protocol/leaderrotation"
	"github.com/relab/hotstuff/protocol/propagator"
	"github.com/relab/hotstuff/protocol/votingmachine"
)

const NameClique = "clique"

// Clique implements one-to-all dissemination and all-to-one aggregation.
type Clique struct {
	config         *core.RuntimeConfig
	votingMachine  *votingmachine.VotingMachine
	leaderRotation leaderrotation.LeaderRotation
	sender         core.Sender
	propagator     *propagator.Propagator
}

// NewClique creates a new Clique instance for communicating proposals and votes.
func NewClique(
	config *core.RuntimeConfig,
	votingMachine *votingmachine.VotingMachine,
	leaderRotation leaderrotation.LeaderRotation,
	sender core.Sender,
	propagator *propagator.Propagator,
) *Clique {
	return &Clique{
		config:         config,
		votingMachine:  votingMachine,
		leaderRotation: leaderRotation,
		sender:         sender,
		propagator:     propagator,
	}
}

// Disseminate broadcasts the proposal and aggregates my vote for this proposals.
func (hs *Clique) Disseminate(proposal *hotstuff.ProposeMsg, pc hotstuff.PartialCert) error {
	hs.sender.Propose(proposal)
	return hs.Aggregate(proposal, pc)
}

// Aggregate sends the vote or stores it if the replica is leader in the next view.
func (hs *Clique) Aggregate(proposal *hotstuff.ProposeMsg, pc hotstuff.PartialCert) error {
	nextView := proposal.Block.View() + 1
	leaderID := hs.leaderRotation.GetLeader(nextView)
	if hs.config.HasNVC() {
		hs.propagator.OnVote(hotstuff.VoteMsg{
			ID:          hs.config.ID(),
			PartialCert: pc,
		})
	} else if leaderID == hs.config.ID() {
		// if I am the leader in the next view, collect the vote for myself beforehand.
		hs.votingMachine.CollectVote(hotstuff.VoteMsg{
			ID:          hs.config.ID(),
			PartialCert: pc,
		})
		return nil
	}

	return hs.sender.Vote(leaderID, pc)
}

var (
	_ Aggregator   = (*Clique)(nil)
	_ Disseminator = (*Clique)(nil)
)
