// Package hotstuffpb contains conversion functions between protocol buffer message types and HotStuff protocol message structures.
package hotstuffpb

import (
	"math/big"

	"github.com/relab/hotstuff"
	"github.com/relab/hotstuff/security/crypto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// QuorumSignatureToProto converts a threshold signature to a protocol buffers message.
func QuorumSignatureToProto(sig hotstuff.QuorumSignature) *QuorumSignature {
	signature := &QuorumSignature{}
	switch ms := sig.(type) {
	case crypto.Multi[*crypto.ECDSASignature]:
		sigs := make([]*ECDSASignature, 0, sig.Participants().Len())
		for _, s := range ms {
			sigs = append(sigs, &ECDSASignature{
				Signer: uint32(s.Signer()),
				R:      s.R().Bytes(),
				S:      s.S().Bytes(),
			})
		}
		signature.Sig = &QuorumSignature_ECDSASigs{ECDSASigs: &ECDSAMultiSignature{
			Sigs: sigs,
		}}

	case crypto.Multi[*crypto.EDDSASignature]:
		sigs := make([]*EDDSASignature, 0, sig.Participants().Len())
		for _, s := range ms {
			sigs = append(sigs, &EDDSASignature{Signer: uint32(s.Signer()), Sig: s.ToBytes()})
		}
		signature.Sig = &QuorumSignature_EDDSASigs{EDDSASigs: &EDDSAMultiSignature{
			Sigs: sigs,
		}}

	case *crypto.BLS12AggregateSignature:
		signature.Sig = &QuorumSignature_BLS12Sig{BLS12Sig: &BLS12AggregateSignature{
			Sig:          ms.ToBytes(),
			Participants: ms.Bitfield().Bytes(),
		}}
	}
	return signature
}

// QuorumSignatureFromProto converts a protocol buffers message to a threshold signature.
func QuorumSignatureFromProto(sig *QuorumSignature) hotstuff.QuorumSignature {
	if signature := sig.GetECDSASigs(); signature != nil {
		sigs := make([]*crypto.ECDSASignature, len(signature.GetSigs()))
		for i, sig := range signature.GetSigs() {
			r := new(big.Int)
			r.SetBytes(sig.GetR())
			s := new(big.Int)
			s.SetBytes(sig.GetS())
			sigs[i] = crypto.RestoreECDSASignature(r, s, hotstuff.ID(sig.GetSigner()))
		}
		return crypto.Restore(sigs)
	}
	if signature := sig.GetEDDSASigs(); signature != nil {
		sigs := make([]*crypto.EDDSASignature, len(signature.GetSigs()))
		for i, sig := range signature.GetSigs() {
			sigs[i] = crypto.RestoreEDDSASignature(sig.Sig, hotstuff.ID(sig.GetSigner()))
		}
		return crypto.Restore(sigs)
	}
	if signature := sig.GetBLS12Sig(); signature != nil {
		aggSig, err := crypto.RestoreBLS12AggregateSignature(signature.GetSig(), crypto.BitfieldFromBytes(signature.GetParticipants()))
		if err != nil {
			return nil
		}
		return aggSig
	}
	return nil
}

// PartialCertToProto converts a hotstuff.PartialCert to a PartialCert.
func PartialCertToProto(cert hotstuff.PartialCert) *PartialCert {
	hash := cert.BlockHash()
	return &PartialCert{
		Sig:  QuorumSignatureToProto(cert.Signature()),
		Hash: hash[:],
	}
}

// PartialCertFromProto converts a PartialCert to a hotstuff.PartialCert.
func PartialCertFromProto(cert *PartialCert) hotstuff.PartialCert {
	var h hotstuff.Hash
	copy(h[:], cert.GetHash())
	return hotstuff.NewPartialCert(QuorumSignatureFromProto(cert.GetSig()), h)
}

func SeenPartialCertToProto(spc hotstuff.SeenPartialCert) *SeenPartialCert {
	hash := spc.BlockHash()
	voter := spc.Voter()
	return &SeenPartialCert{
		Sig:   QuorumSignatureToProto(spc.Signature()),
		Voter: uint32(voter),
		Hash:  hash[:],
	}
}

func SeenPartialCertFromProto(spc *SeenPartialCert) hotstuff.SeenPartialCert {
	var h hotstuff.Hash
	copy(h[:], spc.GetHash())

	return hotstuff.NewSeenPartialCert(
		QuorumSignatureFromProto(spc.GetSig()),
		h,
		hotstuff.ID(spc.GetVoter()),
	)
}

// QuorumCertToProto converts a hotstuff.QuorumCert to a QuorumCert.
func QuorumCertToProto(qc hotstuff.QuorumCert) *QuorumCert {
	hash := qc.BlockHash()
	return &QuorumCert{
		Sig:  QuorumSignatureToProto(qc.Signature()),
		Hash: hash[:],
		View: uint64(qc.View()),
	}
}

// QuorumCertFromProto converts a QuorumCert to a hotstuff.QuorumCert.
func QuorumCertFromProto(qc *QuorumCert) hotstuff.QuorumCert {
	var h hotstuff.Hash
	copy(h[:], qc.GetHash())
	return hotstuff.NewQuorumCert(QuorumSignatureFromProto(qc.GetSig()), hotstuff.View(qc.GetView()), h)
}

// ProposalToProto converts a hotstuff.ProposeMsg to a Proposal.
func ProposalToProto(proposal hotstuff.ProposeMsg) *Proposal {
	p := &Proposal{
		Block: BlockToProto(proposal.Block),
	}
	if proposal.AggregateQC != nil {
		p.AggQC = AggregateQCToProto(*proposal.AggregateQC)
	}
	if proposal.NVC != nil {
		p.NVC = NewViewCertToProto(*proposal.NVC)
	}
	return p
}

// ProposalFromProto converts a Proposal to a hotstuff.ProposeMsg.
func ProposalFromProto(p *Proposal) (proposal hotstuff.ProposeMsg) {
	proposal.Block = BlockFromProto(p.GetBlock())
	if p.GetAggQC() != nil {
		aggQC := AggregateQCFromProto(p.GetAggQC())
		proposal.AggregateQC = &aggQC
	}
	if p.GetNVC() != nil {
		nvc := NewViewCertFromProto(p.GetNVC())
		proposal.NVC = &nvc
	}
	return
}

// BlockToProto converts a hotstuff.Block to a Block.
func BlockToProto(block *hotstuff.Block) *Block {
	parentHash := block.Parent()
	protoBlock := &Block{
		Parent:    parentHash[:],
		Commands:  block.Commands(),
		View:      uint64(block.View()),
		Proposer:  uint32(block.Proposer()),
		Timestamp: timestamppb.New(block.Timestamp()),
	}

	switch c := block.Cert().(type) {
	case hotstuff.QuorumCert:
		protoBlock.Cert = &Block_QC{QuorumCertToProto(c)}
	case hotstuff.QuorumSeenCert:
		protoBlock.Cert = &Block_QSC{QuorumSeenCertToProto(c)}
	}

	return protoBlock
}

// BlockFromProto converts a Block to a hotstuff.Block.
func BlockFromProto(block *Block) *hotstuff.Block {
	var p hotstuff.Hash
	copy(p[:], block.GetParent())

	var cert hotstuff.Cert
	switch c := block.GetCert().(type) {
	case *Block_QC:
		cert = QuorumCertFromProto(c.QC)
	case *Block_QSC:
		cert = QuorumSeenCertFromProto(c.QSC)
	}

	b := hotstuff.NewBlock(
		p,
		cert,
		block.GetCommands(),
		hotstuff.View(block.GetView()),
		hotstuff.ID(block.GetProposer()),
	)
	b.SetTimestamp(block.Timestamp.AsTime())
	return b
}

func QuorumSeenCertFromProto(m *QuorumSeenCert) hotstuff.QuorumSeenCert {
	var h hotstuff.Hash
	copy(h[:], m.GetHash())

	metadata := make(map[hotstuff.ID]hotstuff.IDSet, len(m.GetMetadata()))
	for id, bitfieldBytes := range m.GetMetadata() {
		bitfield := crypto.BitfieldFromBytes(bitfieldBytes)
		metadata[hotstuff.ID(id)] = &bitfield
	}

	return hotstuff.NewQuorumSeenCert(
		QuorumSignatureFromProto(m.GetSig()),
		metadata,
		hotstuff.View(m.GetView()),
		h,
	)
}

func QuorumSeenCertToProto(qsc hotstuff.QuorumSeenCert) *QuorumSeenCert {
	protoMeta := make(map[uint32][]byte, len(qsc.Metadata()))
	for voter, idSet := range qsc.Metadata() {
		if bitfield, ok := idSet.(*crypto.Bitfield); ok {
			protoMeta[uint32(voter)] = bitfield.Bytes()
		}
	}
	hash := qsc.BlockHash()

	return &QuorumSeenCert{
		Sig:      QuorumSignatureToProto(qsc.Signature()),
		Metadata: protoMeta,
		View:     uint64(qsc.View()),
		Hash:     hash[:],
	}
}

func NewViewCertToProto(nvc hotstuff.NewViewCert) *NewViewCert {
	pQSCs := make(map[uint32]*QuorumSeenCert, len(nvc.QSCs()))
	for id, qsc := range nvc.QSCs() {
		pQSCs[uint32(id)] = QuorumSeenCertToProto(qsc)
	}
	pVoteSigs := make([]*VoteSigEntry, 0, len(nvc.VoteSigs()))
	for vote, idSet := range nvc.VoteSigs() {
		if bitfield, ok := idSet.(*crypto.Bitfield); ok {
			entry := &VoteSigEntry{
				VoteSig: PartialCertToProto(hotstuff.PartialCertFromVoteSignature(vote)),
				IDSet:   bitfield.Bytes(),
			}
			pVoteSigs = append(pVoteSigs, entry)
		}
	}

	anchor := nvc.Anchor()
	return &NewViewCert{
		QSCs:     pQSCs,
		Sig:      QuorumSignatureToProto(nvc.Sig()),
		VoteSig:  QuorumSignatureToProto(nvc.VoteSig()),
		Anchor:   anchor[:],
		View:     uint64(nvc.View()),
		VoteSigs: pVoteSigs,
	}
}

func NewViewCertFromProto(m *NewViewCert) hotstuff.NewViewCert {
	qscs := make(map[hotstuff.ID]hotstuff.QuorumSeenCert)
	var anchor hotstuff.Hash
	for id, pQSC := range m.GetQSCs() {
		qscs[hotstuff.ID(id)] = QuorumSeenCertFromProto(pQSC)
	}
	copy(anchor[:], m.GetAnchor())

	voteSigsMap := make(map[hotstuff.VoteSignature]hotstuff.IDSet)
	protoVoteSigs := m.GetVoteSigs()
	for _, entry := range protoVoteSigs {
		pc := PartialCertFromProto(entry.GetVoteSig())
		vs := hotstuff.VoteSignatureFromPartialCert(pc)
		idSet := crypto.BitfieldFromBytes(entry.GetIDSet())
		voteSigsMap[vs] = &idSet
	}

	return hotstuff.NewNewViewCert(qscs, QuorumSignatureFromProto(m.GetSig()),
		QuorumSignatureFromProto(m.GetVoteSig()), anchor, hotstuff.View(m.GetView()), voteSigsMap)
}

// TimeoutMsgFromProto converts a TimeoutMsg to a hotstuff.TimeoutMsg.
func TimeoutMsgFromProto(m *TimeoutMsg) hotstuff.TimeoutMsg {
	timeoutMsg := hotstuff.TimeoutMsg{
		View:          hotstuff.View(m.GetView()),
		SyncInfo:      SyncInfoFromProto(m.GetSyncInfo()),
		ViewSignature: QuorumSignatureFromProto(m.GetViewSig()),
	}
	if m.GetMsgSig() != nil {
		timeoutMsg.MsgSignature = QuorumSignatureFromProto(m.GetMsgSig())
	}
	return timeoutMsg
}

// TimeoutMsgToProto converts a hotstuff.TimeoutMsg to a TimeoutMsg.
func TimeoutMsgToProto(timeoutMsg hotstuff.TimeoutMsg) *TimeoutMsg {
	tm := &TimeoutMsg{
		View:     uint64(timeoutMsg.View),
		SyncInfo: SyncInfoToProto(timeoutMsg.SyncInfo),
		ViewSig:  QuorumSignatureToProto(timeoutMsg.ViewSignature),
	}
	if timeoutMsg.MsgSignature != nil {
		tm.MsgSig = QuorumSignatureToProto(timeoutMsg.MsgSignature)
	}
	return tm
}

// TimeoutCertFromProto converts a TimeoutCert to a hotstuff.TimeoutCert.
func TimeoutCertFromProto(m *TimeoutCert) hotstuff.TimeoutCert {
	return hotstuff.NewTimeoutCert(QuorumSignatureFromProto(m.GetSig()), hotstuff.View(m.GetView()))
}

// TimeoutCertToProto converts a hotstuff.TimeoutCert to a TimeoutCert.
func TimeoutCertToProto(timeoutCert hotstuff.TimeoutCert) *TimeoutCert {
	return &TimeoutCert{
		View: uint64(timeoutCert.View()),
		Sig:  QuorumSignatureToProto(timeoutCert.Signature()),
	}
}

// AggregateQCFromProto converts an AggQC to a hotstuff.AggregateQC.
func AggregateQCFromProto(m *AggQC) hotstuff.AggregateQC {
	qcs := make(map[hotstuff.ID]hotstuff.QuorumCert)
	for id, pQC := range m.GetQCs() {
		qcs[hotstuff.ID(id)] = QuorumCertFromProto(pQC)
	}
	return hotstuff.NewAggregateQC(qcs, QuorumSignatureFromProto(m.GetSig()), hotstuff.View(m.GetView()))
}

// AggregateQCToProto converts a hotstuff.AggregateQC to an AggQC.
func AggregateQCToProto(aggQC hotstuff.AggregateQC) *AggQC {
	pQCs := make(map[uint32]*QuorumCert, len(aggQC.QCs()))
	for id, qc := range aggQC.QCs() {
		pQCs[uint32(id)] = QuorumCertToProto(qc)
	}
	return &AggQC{QCs: pQCs, Sig: QuorumSignatureToProto(aggQC.Sig()), View: uint64(aggQC.View())}
}

// SyncInfoFromProto converts a SyncInfo message to a hotstuff.SyncInfo.
func SyncInfoFromProto(m *SyncInfo) hotstuff.SyncInfo {
	si := hotstuff.NewSyncInfo()
	if qc := m.GetQC(); qc != nil {
		si = si.WithQC(QuorumCertFromProto(qc))
	}
	if tc := m.GetTC(); tc != nil {
		si = si.WithTC(TimeoutCertFromProto(tc))
	}
	if aggQC := m.GetAggQC(); aggQC != nil {
		si = si.WithAggQC(AggregateQCFromProto(aggQC))
	}
	if qsc := m.GetQSC(); qsc != nil {
		si = si.WithQSC(QuorumSeenCertFromProto(qsc))
	}
	if nvc := m.GetNVC(); nvc != nil {
		si = si.WithNVC(NewViewCertFromProto(nvc))
	}
	return si
}

// SyncInfoToProto converts a hotstuff.SyncInfo to a SyncInfo message.
func SyncInfoToProto(syncInfo hotstuff.SyncInfo) *SyncInfo {
	m := &SyncInfo{}
	if qc, ok := syncInfo.QC(); ok {
		m.QC = QuorumCertToProto(qc)
	}
	if tc, ok := syncInfo.TC(); ok {
		m.TC = TimeoutCertToProto(tc)
	}
	if aggQC, ok := syncInfo.AggQC(); ok {
		m.AggQC = AggregateQCToProto(aggQC)
	}
	if qsc, ok := syncInfo.QSC(); ok {
		m.QSC = QuorumSeenCertToProto(qsc)
	}
	if nvc, ok := syncInfo.NVC(); ok {
		m.NVC = NewViewCertToProto(nvc)
	}
	return m
}
