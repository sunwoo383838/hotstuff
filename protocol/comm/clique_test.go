package comm_test

import (
	"bytes"
	"github.com/relab/hotstuff/protocol/propagator"
	"testing"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/internal/testutil"
	"github.com/relab/hotstuff/protocol"
	"github.com/relab/hotstuff/protocol/comm"
	"github.com/relab/hotstuff/protocol/leaderrotation"
	"github.com/relab/hotstuff/protocol/votingmachine"
	"github.com/relab/hotstuff/security/crypto"
)

type leaderRotation struct{}

func (ld *leaderRotation) GetLeader(view hotstuff.View) hotstuff.ID {
	return hotstuff.ID(view) // simple leader that casts view to leader ID
}

var _ leaderrotation.LeaderRotation = (*leaderRotation)(nil)

func TestDisseminateAggregate(t *testing.T) {
	essentials := testutil.WireUpEssentials(t, 1, crypto.NameECDSA)
	viewStates, err := protocol.NewViewStates(
		essentials.Blockchain(),
		essentials.Authority(),
		essentials.RuntimeCfg(),
	)
	if err != nil {
		t.Fatal(err)
	}
	votingMachine := votingmachine.New(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)

	voteCollector := propagator.NewVoteCollector(essentials.RuntimeCfg())
	seenMachine := votingmachine.NewSeenMachine(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)
	propagator := propagator.NewPropagator(
		essentials.RuntimeCfg(),
		essentials.EventLoop(),
		essentials.Logger(),
		&leaderRotation{},
		viewStates,
		essentials.Authority(),
		voteCollector,
		essentials.Blockchain(),
		essentials.MockSender(),
		seenMachine,
	)

	clique := comm.NewClique(
		essentials.RuntimeCfg(),
		votingMachine,
		&leaderRotation{},
		essentials.MockSender(),
		propagator,
	)
	block := testutil.CreateBlock(t, essentials.Authority())
	pc := testutil.CreatePC(t, block, essentials.Authority())
	proposal := &hotstuff.ProposeMsg{
		ID:    1,
		Block: block,
	}
	err = clique.Disseminate(proposal, pc)
	if err != nil {
		t.Fatal(err)
	}
	messages := essentials.MockSender().MessagesSent()
	if len(messages) != 2 {
		t.Fatal("expected two messages to be sent")
	}
	msgProposal, ok := messages[0].(hotstuff.ProposeMsg)
	if !ok {
		t.Fatal("incorrect message type was sent")
	}
	if msgProposal.ID != proposal.ID || msgProposal.Block != proposal.Block {
		t.Fatal("incorrect message data")
	}

	// checking the second message
	msgPC, ok := messages[1].(hotstuff.PartialCert)
	if !ok {
		t.Fatal("incorrect message type was sent")
	}
	if !bytes.Equal(msgPC.ToBytes(), pc.ToBytes()) {
		t.Fatal("incorrect message data")
	}
}

func TestAggregateSend(t *testing.T) {
	essentials := testutil.WireUpEssentials(t, 1, crypto.NameECDSA)
	viewStates, err := protocol.NewViewStates(
		essentials.Blockchain(),
		essentials.Authority(),
		essentials.RuntimeCfg(),
	)
	if err != nil {
		t.Fatal(err)
	}
	votingMachine := votingmachine.New(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)

	voteCollector := propagator.NewVoteCollector(essentials.RuntimeCfg())
	seenMachine := votingmachine.NewSeenMachine(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)
	propagator := propagator.NewPropagator(
		essentials.RuntimeCfg(),
		essentials.EventLoop(),
		essentials.Logger(),
		&leaderRotation{},
		viewStates,
		essentials.Authority(),
		voteCollector,
		essentials.Blockchain(),
		essentials.MockSender(),
		seenMachine,
	)

	clique := comm.NewClique(
		essentials.RuntimeCfg(),
		votingMachine,
		&leaderRotation{},
		essentials.MockSender(),
		propagator,
	)
	block := testutil.CreateBlock(t, essentials.Authority())
	pc := testutil.CreatePC(t, block, essentials.Authority())
	proposal := &hotstuff.ProposeMsg{
		ID:    1,
		Block: block,
	}

	// Replica 1 is not leader of next view 2
	err = clique.Aggregate(proposal, pc)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that a message was sent
	messages := essentials.MockSender().MessagesSent()
	if len(messages) != 1 {
		t.Fatal("expected one message to be sent")
	}

	// Check if the message is a partial certificate
	_, ok := messages[0].(hotstuff.PartialCert)
	if !ok {
		t.Fatal("incorrect message type was sent")
	}
}

func TestAggregateStore(t *testing.T) {
	essentials := testutil.WireUpEssentials(t, 2, crypto.NameECDSA)
	viewStates, err := protocol.NewViewStates(
		essentials.Blockchain(),
		essentials.Authority(),
		essentials.RuntimeCfg(),
	)
	if err != nil {
		t.Fatal(err)
	}
	votingMachine := votingmachine.New(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)

	voteCollector := propagator.NewVoteCollector(essentials.RuntimeCfg())
	seenMachine := votingmachine.NewSeenMachine(
		essentials.Logger(),
		essentials.EventLoop(),
		essentials.RuntimeCfg(),
		essentials.Blockchain(),
		essentials.Authority(),
		viewStates,
	)
	propagator := propagator.NewPropagator(
		essentials.RuntimeCfg(),
		essentials.EventLoop(),
		essentials.Logger(),
		&leaderRotation{},
		viewStates,
		essentials.Authority(),
		voteCollector,
		essentials.Blockchain(),
		essentials.MockSender(),
		seenMachine,
	)

	clique := comm.NewClique(
		essentials.RuntimeCfg(),
		votingMachine,
		&leaderRotation{},
		essentials.MockSender(),
		propagator,
	)
	block := testutil.CreateBlock(t, essentials.Authority())
	pc := testutil.CreatePC(t, block, essentials.Authority())
	proposal := &hotstuff.ProposeMsg{
		ID:    1,
		Block: block,
	}

	// Replica 2 is leader of view 2
	err = clique.Aggregate(proposal, pc)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that no message was sent
	messages := essentials.MockSender().MessagesSent()
	if len(messages) != 0 {
		t.Fatal("expected no message to be sent")
	}
}
