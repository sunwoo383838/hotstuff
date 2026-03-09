// Package votingmachine collects and verifies votes.
package votingmachine

import (
	"sync"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/core"
	"github.com/relab/hotstuff/core/eventloop"
	"github.com/relab/hotstuff/core/logging"
	"github.com/relab/hotstuff/protocol"
	"github.com/relab/hotstuff/security/blockchain"
	"github.com/relab/hotstuff/security/cert"
)

type seenBucket struct {
	mu       sync.Mutex
	verified []hotstuff.SeenPartialCert
	pending  []hotstuff.SeenPartialCert
	hasSC    bool
}

type perBlock struct {
	mu           sync.RWMutex
	seenByVoters map[hotstuff.ID]*seenBucket
	scByVoters   map[hotstuff.ID]hotstuff.SeenCert
	view         hotstuff.View
	qscBuilt     bool
}

// VotingMachine collects and verifies votes.
type SeenMachine struct {
	logger     logging.Logger
	eventLoop  *eventloop.EventLoop
	config     *core.RuntimeConfig
	blockchain *blockchain.Blockchain
	auth       *cert.Authority
	state      *protocol.ViewStates

	blocksMu sync.RWMutex
	blocks   map[hotstuff.Hash]*perBlock
}

func NewSeenMachine(
	logger logging.Logger,
	eventLoop *eventloop.EventLoop,
	config *core.RuntimeConfig,
	blockchain *blockchain.Blockchain,
	auth *cert.Authority,
	state *protocol.ViewStates,
) *SeenMachine {
	vm := &SeenMachine{
		blockchain: blockchain,
		auth:       auth,
		eventLoop:  eventLoop,
		logger:     logger,
		config:     config,
		state:      state,
		blocks:     make(map[hotstuff.Hash]*perBlock),
	}

	if config.HasNVC() {
		vm.eventLoop.RegisterHandler(hotstuff.SeenMsg{}, func(event any) {
			vm.CollectSeen(event.(hotstuff.SeenMsg))
		})
	}

	return vm
}

// CollectVote handles an incoming vote.
func (sm *SeenMachine) CollectSeen(seen hotstuff.SeenMsg) {
	cert := seen.SeenPartialCert
	sm.logger.Debugf("OnSeen(%d): %.8s", seen.ID, cert.BlockHash())

	var (
		block *hotstuff.Block
		ok    bool
	)

	if !seen.Deferred {
		block, ok = sm.blockchain.LocalGet(cert.BlockHash())
		if !ok {
			sm.logger.Debugf("Local cache miss for block: %.8s", cert.BlockHash())
			seen.Deferred = true
			sm.eventLoop.DelayUntil(hotstuff.ProposeMsg{}, seen)
			return
		}
	} else {
		block, ok = sm.blockchain.Get(cert.BlockHash())
		if !ok {
			sm.logger.Debugf("Could not find block for vote: %.8s.", cert.BlockHash())
			return
		}
	}

	if block.View() <= sm.state.HighQSC().View() {
		sm.logger.Info("block too old")
		return
	}
	go sm.verifySeenPartialCert(cert, block)
}

func (sm *SeenMachine) verifySeenPartialCert(cert hotstuff.SeenPartialCert, block *hotstuff.Block) {
	hash := block.Hash()
	voter := cert.Voter()
	quorumSize := sm.config.QuorumSize()

	sm.blocksMu.RLock()
	pb := sm.blocks[hash]
	sm.blocksMu.RUnlock()
	if pb == nil {
		sm.blocksMu.Lock()
		pb = sm.blocks[hash]
		if pb == nil {
			pb = &perBlock{
				seenByVoters: make(map[hotstuff.ID]*seenBucket),
				scByVoters:   make(map[hotstuff.ID]hotstuff.SeenCert),
				view:         block.View(),
			}
			sm.blocks[hash] = pb
		}
		sm.blocksMu.Unlock()
	}

	pb.mu.Lock()
	vb := pb.seenByVoters[voter]
	if vb == nil {
		vb = &seenBucket{}
		pb.seenByVoters[voter] = vb
	}
	pb.mu.Unlock()

	vb.mu.Lock()
	if vb.hasSC {
		vb.mu.Unlock()
		return
	}
	vb.pending = append(vb.pending, cert)
	total := len(vb.verified) + len(vb.pending)
	if total < quorumSize {
		vb.mu.Unlock()
		return
	}
	sm.logger.Debugf("쿼럼 사이즈 넘음: voter %d", voter)

	batch := make([]hotstuff.SeenPartialCert, len(vb.pending))
	copy(batch, vb.pending)
	vb.pending = vb.pending[:0]
	vb.mu.Unlock()
	if sc, ok := sm.auth.VerifyAndCreateSeenCert(batch); ok {
		vb.mu.Lock()
		if vb.hasSC {
			vb.mu.Unlock()
			return
		}
		vb.hasSC = true
		vb.mu.Unlock()
		sm.verifySeenCert(pb, block, sc)
		return
	}

	vb.mu.Lock()
	if vb.hasSC {
		vb.mu.Unlock()
		return
	}
	for _, c := range batch {
		if c.IsVerified() {
			vb.verified = append(vb.verified, c)
		}
	}

	vb.pending = vb.pending[:0]
	var needCreateSC bool
	var verifiedSnapshot []hotstuff.SeenPartialCert
	if !vb.hasSC && len(vb.verified) >= quorumSize {
		vb.hasSC = true
		verifiedSnapshot = append(verifiedSnapshot, vb.verified...)
		needCreateSC = true
	}
	vb.mu.Unlock()

	if needCreateSC {
		sc, err := sm.auth.CreateSeenCert(hash, voter, verifiedSnapshot)
		sm.logger.Debug("createseencert")
		if err != nil {
			sm.logger.Warnf("CreateSeenCert 실패 (block=%.8s voter=%d): %v", hash, voter, err)
		} else {
			sm.verifySeenCert(pb, block, sc)
		}
	}
}

func (sm *SeenMachine) verifySeenCert(pb *perBlock, block *hotstuff.Block, sc hotstuff.SeenCert) {
	quorumSize := sm.config.QuorumSize()
	sm.logger.Debugf("verify seen cert진입, block : %s", block)
	pb.mu.Lock()
	if pb.qscBuilt {
		pb.mu.Unlock()
		return
	}
	if _, ok := pb.scByVoters[sc.Voter()]; ok {
		pb.mu.Unlock()
		return
	}
	pb.scByVoters[sc.Voter()] = sc

	if len(pb.scByVoters) < quorumSize {
		pb.mu.Unlock()
		return
	}

	pb.qscBuilt = true
	all := make([]hotstuff.SeenCert, 0, len(pb.scByVoters))
	for _, vsc := range pb.scByVoters {
		all = append(all, vsc)
	}
	pb.mu.Unlock()

	qsc, err := sm.auth.CreateQuorumSeenCert(block, all)
	if err != nil {
		sm.logger.Warnf("AggregateSeenCert 실패 (block=%.8s): %v", block.Hash(), err)
		return
	}
	sm.logger.Debugf("인증서생성, qsc : %s", qsc)

	sm.blocksMu.Lock()
	delete(sm.blocks, block.Hash())
	sm.blocksMu.Unlock()

	sm.eventLoop.AddEvent(hotstuff.NewViewMsg{
		ID:       sm.config.ID(),
		SyncInfo: hotstuff.NewSyncInfo().WithQSC(qsc),
	})
}
