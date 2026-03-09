package hotstuff

import (
	"time"

	"github.com/relab/hotstuff/internal/proto/clientpb"
)

// genesisBlock is initialized at package initialization time.
var genesisBlock = func() *Block {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewBlock(Hash{}, QuorumCert{}, &clientpb.Batch{}, 0, 0)
	b.SetTimestamp(ts)
	return b
}()

var genesisQSCBlock = func() *Block {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewBlock(Hash{}, QuorumSeenCert{}, &clientpb.Batch{}, 0, 0)
	b.SetTimestamp(ts)
	return b
}()

// GetGenesis returns the genesis block.
func GetGenesis() *Block {
	return genesisBlock
}

func GetGenesisQSC() *Block {
	return genesisQSCBlock
}
