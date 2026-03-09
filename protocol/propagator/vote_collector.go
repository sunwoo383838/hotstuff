package propagator

import (
	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"slices"
)

type VoteCollector struct {
	config *core.RuntimeConfig
	votes  map[hotstuff.View][]hotstuff.VoteSignature
}

func NewVoteCollector(config *core.RuntimeConfig) *VoteCollector {
	return &VoteCollector{
		config: config,
		votes:  make(map[hotstuff.View][]hotstuff.VoteSignature),
	}
}

// add returns true if a quorum of timeouts has been collected for the view of given timeout message.
func (vc *VoteCollector) Add(voteSig hotstuff.VoteSignature, view hotstuff.View) {
	// ignore this timeout if we already have a timeout from this replica in this view
	if slices.ContainsFunc(vc.votes[view], func(vs hotstuff.VoteSignature) bool {
		return vs.Id() == voteSig.Id()
	}) {
		return
	}
	vc.votes[view] = append(vc.votes[view], voteSig)
}

func (vc *VoteCollector) Get(currentView hotstuff.View) []hotstuff.VoteSignature {
	return vc.votes[currentView]
}

// deleteOldViews removes all timeouts with a view lower than the current view.
// This is used to clean up timeouts that are no longer relevant, as they are from
// an already processed view.
func (vc *VoteCollector) DeleteOldViews(currentView hotstuff.View) {
	delete(vc.votes, currentView-1)
}
