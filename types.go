package hotstuff

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// IDSet implements a set of replica IDs. It is used to show which replicas participated in some event.
type IDSet interface {
	// Add adds an ID to the set.
	Add(id ID)
	// Contains returns true if the set contains the ID.
	Contains(id ID) bool
	// ForEach calls f for each ID in the set.
	ForEach(f func(ID))
	// RangeWhile calls f for each ID in the set until f returns false.
	RangeWhile(f func(ID) bool)
	// Len returns the number of entries in the set.
	Len() int
	ToBytes
}

// IDSetToString formats an IDSet as a string.
func IDSetToString(set IDSet) string {
	var sb strings.Builder
	sb.WriteString("[ ")
	set.ForEach(func(i ID) {
		sb.WriteString(strconv.Itoa(int(i)))
		sb.WriteString(" ")
	})
	sb.WriteString("]")
	return sb.String()
}

// View is a number that uniquely identifies a view.
type View uint64

// ToBytes returns the view as bytes.
func (v View) ToBytes() []byte {
	var viewBytes [8]byte
	binary.LittleEndian.PutUint64(viewBytes[:], uint64(v))
	return viewBytes[:]
}

// Hash is a SHA256 hash
type Hash [32]byte

func (h Hash) String() string {
	return base64.StdEncoding.EncodeToString(h[:])
}

// SmallString returns a 6-character string version of the hash
func (h Hash) SmallString() string {
	return base64.StdEncoding.EncodeToString(h[:6])
}

var _ fmt.Stringer = (*Hash)(nil)

// ToBytes is an object that can be converted into bytes for the purposes of hashing, etc.
type ToBytes interface {
	// ToBytes returns the object as bytes.
	ToBytes() []byte
}

// PublicKey is the public part of a replica's key pair.
type PublicKey = crypto.PublicKey

// PrivateKey is the private part of a replica's key pair.
type PrivateKey interface {
	// Public returns the public key associated with this private key.
	Public() PublicKey
}

// QuorumSignature is a signature that is only valid when it contains the signatures of a quorum of replicas.
type QuorumSignature interface {
	ToBytes
	// Participants returns the IDs of replicas who participated in the threshold signature.
	Participants() IDSet
}

// ThresholdSignature is a signature that is only valid when it contains the signatures of a quorum of replicas.
//
// Deprecated: renamed to QuorumSignature
type ThresholdSignature = QuorumSignature

// PartialCert is a signed block hash.
type PartialCert struct {
	// shortcut to the signer of the signature
	signer    ID
	signature QuorumSignature
	blockHash Hash
}

// NewPartialCert returns a new partial certificate.
func NewPartialCert(signature QuorumSignature, blockHash Hash) PartialCert {
	var signer ID
	signature.Participants().RangeWhile(func(i ID) bool {
		signer = i
		return false
	})
	return PartialCert{signer, signature, blockHash}
}

// Signer returns the ID of the replica that created the certificate.
func (pc PartialCert) Signer() ID {
	return pc.signer
}

// Signature returns the signature.
func (pc PartialCert) Signature() QuorumSignature {
	return pc.signature
}

// BlockHash returns the hash of the block that was signed.
func (pc PartialCert) BlockHash() Hash {
	return pc.blockHash
}

// ToBytes returns a byte representation of the partial certificate.
func (pc PartialCert) ToBytes() []byte {
	return append(pc.blockHash[:], pc.signature.ToBytes()...)
}

// SyncInfo holds the highest known QC or TC.
// Generally, if highQC.View > highTC.View, there is no need to include highTC in the SyncInfo.
// However, if highQC.View < highTC.View, we should still include highQC.
// This can also hold an AggregateQC for Fast-HotStuff.
type SyncInfo struct {
	qc    *QuorumCert
	tc    *TimeoutCert
	aggQC *AggregateQC
	qsc   *QuorumSeenCert
	nvc   *NewViewCert
}

// NewSyncInfo returns a new SyncInfo struct.
func NewSyncInfo() SyncInfo {
	return SyncInfo{}
}

// WithQC returns a copy of the SyncInfo struct with the given QC.
func (si SyncInfo) WithQC(qc QuorumCert) SyncInfo {
	si.qc = new(QuorumCert)
	*si.qc = qc
	return si
}

// WithTC returns a copy of the SyncInfo struct with the given TC.
func (si SyncInfo) WithTC(tc TimeoutCert) SyncInfo {
	si.tc = new(TimeoutCert)
	*si.tc = tc
	return si
}

// WithAggQC returns a copy of the SyncInfo struct with the given AggregateQC.
func (si SyncInfo) WithAggQC(aggQC AggregateQC) SyncInfo {
	si.aggQC = new(AggregateQC)
	*si.aggQC = aggQC
	return si
}

func (si SyncInfo) WithQSC(qsc QuorumSeenCert) SyncInfo {
	si.qsc = new(QuorumSeenCert)
	*si.qsc = qsc
	return si
}

func (si SyncInfo) WithNVC(nvc NewViewCert) SyncInfo {
	si.nvc = new(NewViewCert)
	*si.nvc = nvc
	return si
}

// QC returns the quorum certificate, if present.
func (si SyncInfo) QC() (_ QuorumCert, _ bool) {
	if si.qc != nil {
		return *si.qc, true
	}
	return
}

// TC returns the timeout certificate, if present.
func (si SyncInfo) TC() (_ TimeoutCert, _ bool) {
	if si.tc != nil {
		return *si.tc, true
	}
	return
}

// AggQC returns the AggregateQC, if present.
func (si SyncInfo) AggQC() (_ AggregateQC, _ bool) {
	if si.aggQC != nil {
		return *si.aggQC, true
	}
	return
}

func (si SyncInfo) QSC() (_ QuorumSeenCert, _ bool) {
	if si.qsc != nil {
		return *si.qsc, true
	}
	return
}

func (si SyncInfo) NVC() (_ NewViewCert, _ bool) {
	if si.nvc != nil {
		return *si.nvc, true
	}
	return
}

func (si SyncInfo) String() string {
	var sb strings.Builder
	sb.WriteString("{ ")
	if si.tc != nil {
		fmt.Fprintf(&sb, "%s ", si.tc)
	}
	if si.qc != nil {
		fmt.Fprintf(&sb, "%s ", si.qc)
	}
	if si.aggQC != nil {
		fmt.Fprintf(&sb, "%s ", si.aggQC)
	}
	if si.qsc != nil {
		fmt.Fprintf(&sb, "%s ", si.qsc)
	}
	if si.nvc != nil {
		fmt.Fprintf(&sb, "%s ", si.nvc)
	}
	sb.WriteRune('}')
	return sb.String()
}

var _ fmt.Stringer = (*SyncInfo)(nil)

// QuorumCert (QC) is a certificate for a Block created by a quorum of partial certificates.
type QuorumCert struct {
	signature QuorumSignature
	view      View
	hash      Hash
}

// NewQuorumCert creates a new quorum cert from the given values.
func NewQuorumCert(signature QuorumSignature, view View, hash Hash) QuorumCert {
	return QuorumCert{signature, view, hash}
}

// ToBytes returns a byte representation of the quorum certificate.
func (qc QuorumCert) ToBytes() []byte {
	b := qc.view.ToBytes()
	b = append(b, qc.hash[:]...)
	if qc.signature != nil {
		b = append(b, qc.signature.ToBytes()...)
	}
	return b
}

// Signature returns the threshold signature.
func (qc QuorumCert) Signature() QuorumSignature {
	return qc.signature
}

// BlockHash returns the hash of the block that was signed.
func (qc QuorumCert) BlockHash() Hash {
	return qc.hash
}

// View returns the view in which the QC was created.
func (qc QuorumCert) View() View {
	return qc.view
}

// Equals returns true if the other QC equals this QC.
func (qc QuorumCert) Equals(other QuorumCert) bool {
	if qc.view != other.view {
		return false
	}
	if qc.hash != other.hash {
		return false
	}
	if qc.signature == nil || other.signature == nil {
		return qc.signature == other.signature
	}
	return bytes.Equal(qc.signature.ToBytes(), other.signature.ToBytes())
}

func (qc QuorumCert) String() string {
	var sb strings.Builder
	if qc.signature != nil {
		_ = writeParticipants(&sb, qc.Signature().Participants())
	}
	return fmt.Sprintf("QC{ hash: %s, view: %d, IDs: [ %s] }", qc.hash.SmallString(), qc.view, &sb)
}

var _ fmt.Stringer = (*QuorumCert)(nil)

// TimeoutCert (TC) is a certificate created by a quorum of timeout messages.
type TimeoutCert struct {
	signature QuorumSignature
	view      View
}

// NewTimeoutCert returns a new timeout certificate.
func NewTimeoutCert(signature QuorumSignature, view View) TimeoutCert {
	return TimeoutCert{signature, view}
}

// ToBytes returns a byte representation of the timeout certificate.
func (tc TimeoutCert) ToBytes() []byte {
	var viewBytes [8]byte
	binary.LittleEndian.PutUint64(viewBytes[:], uint64(tc.view))
	return append(viewBytes[:], tc.signature.ToBytes()...)
}

// Signature returns the threshold signature.
func (tc TimeoutCert) Signature() QuorumSignature {
	return tc.signature
}

// View returns the view in which the timeouts occurred.
func (tc TimeoutCert) View() View {
	return tc.view
}

func (tc TimeoutCert) String() string {
	var sb strings.Builder
	if tc.signature != nil {
		_ = writeParticipants(&sb, tc.Signature().Participants())
	}
	return fmt.Sprintf("TC{ view: %d, IDs: [ %s] }", tc.view, &sb)
}

var _ fmt.Stringer = (*TimeoutCert)(nil)

// AggregateQC is a set of QCs extracted from timeout messages and an aggregate signature of the timeout signatures.
//
// This is used by the Fast-HotStuff consensus protocol.
type AggregateQC struct {
	qcs  map[ID]QuorumCert
	sig  QuorumSignature
	view View
}

// NewAggregateQC returns a new AggregateQC from the QC map and the threshold signature.
func NewAggregateQC(qcs map[ID]QuorumCert, sig QuorumSignature, view View) AggregateQC {
	return AggregateQC{qcs, sig, view}
}

// QCs returns the quorum certificates in the AggregateQC.
func (aggQC AggregateQC) QCs() map[ID]QuorumCert {
	return aggQC.qcs
}

// Sig returns the threshold signature in the AggregateQC.
func (aggQC AggregateQC) Sig() QuorumSignature {
	return aggQC.sig
}

// View returns the view in which the AggregateQC was created.
func (aggQC AggregateQC) View() View {
	return aggQC.view
}

func (aggQC AggregateQC) String() string {
	var sb strings.Builder
	if aggQC.sig != nil {
		_ = writeParticipants(&sb, aggQC.sig.Participants())
	}
	return fmt.Sprintf("AggQC{ view: %d, IDs: [ %s] }", aggQC.view, &sb)
}

type VoteSignatureSet struct {
	members map[string]VoteSignature
}

func NewVoteSignatureSet() *VoteSignatureSet {
	return &VoteSignatureSet{
		members: make(map[string]VoteSignature),
	}
}

func (s *VoteSignatureSet) key(vote VoteSignature) string {
	if vote.signature == nil {
		return ""
	}
	return string(vote.signature.ToBytes())
}

func (s *VoteSignatureSet) Add(vote VoteSignature) {
	s.members[s.key(vote)] = vote
}

func (s *VoteSignatureSet) Contains(vote VoteSignature) bool {
	_, ok := s.members[s.key(vote)]
	return ok
}

func (s *VoteSignatureSet) Remove(vote VoteSignature) {
	delete(s.members, s.key(vote))
}

func (s *VoteSignatureSet) ForEach(f func(VoteSignature)) {
	for _, vote := range s.members {
		f(vote)
	}
}

func (s *VoteSignatureSet) AddAll(other *VoteSignatureSet) {
	other.ForEach(func(vote VoteSignature) {
		s.Add(vote)
	})
}

func (s *VoteSignatureSet) Len() int {
	return len(s.members)
}

func (s *VoteSignatureSet) ToSlice() []VoteSignature {
	slice := make([]VoteSignature, 0, s.Len())
	s.ForEach(func(vote VoteSignature) {
		slice = append(slice, vote)
	})
	return slice
}

func (s *VoteSignatureSet) ToBytes() []byte {
	if s.Len() == 0 {
		return nil
	}

	slice := s.ToSlice()

	sort.Slice(slice, func(i, j int) bool {
		return slice[i].id < slice[j].id
	})

	var b bytes.Buffer
	for _, vote := range slice {
		b.Write(vote.ToBytes())
	}

	return b.Bytes()
}

type VoteSignature struct {
	id        ID
	hash      Hash
	signature QuorumSignature
}

func (v VoteSignature) Id() ID {
	return v.id
}

func (v VoteSignature) Hash() Hash {
	return v.hash
}

func (v VoteSignature) Signature() QuorumSignature {
	return v.signature
}

func (v VoteSignature) ToBytes() []byte {
	b := v.id.ToBytes()
	b = append(b, v.hash[:]...)
	b = append(b, v.signature.ToBytes()...)
	return b
}

func (v VoteSignature) String() string {
	return fmt.Sprintf("[hash: %s, voter: %d]", v.hash.SmallString(), v.id)
}

func VoteSignatureFromPartialCert(pc PartialCert) VoteSignature {
	return VoteSignature{
		id:        pc.signer,
		hash:      pc.blockHash,
		signature: pc.signature,
	}
}

func PartialCertFromVoteSignature(vs VoteSignature) PartialCert {
	return PartialCert{
		signer:    vs.id,
		blockHash: vs.hash,
		signature: vs.signature,
	}
}

func NewVoteSignature(id ID, hash Hash, signature QuorumSignature) VoteSignature {
	return VoteSignature{id: id, hash: hash, signature: signature}
}

type NewViewCert struct {
	qscs     map[ID]QuorumSeenCert
	sig      QuorumSignature
	voteSig  QuorumSignature
	anchor   Hash
	view     View
	voteSigs map[VoteSignature]IDSet
}

func NewNewViewCert(qscs map[ID]QuorumSeenCert, sig QuorumSignature,
	voteSig QuorumSignature, anchor Hash, view View, voteSigs map[VoteSignature]IDSet) NewViewCert {
	return NewViewCert{qscs: qscs, sig: sig, voteSig: voteSig,
		anchor: anchor, view: view, voteSigs: voteSigs}
}

func (nvc NewViewCert) View() View {
	return nvc.view
}

func (nvc NewViewCert) Anchor() Hash {
	return nvc.anchor
}

func (nvc NewViewCert) VoteSig() QuorumSignature {
	return nvc.voteSig
}

func (nvc NewViewCert) Sig() QuorumSignature {
	return nvc.sig
}

func (nvc NewViewCert) QSCs() map[ID]QuorumSeenCert {
	return nvc.qscs
}

func (nvc NewViewCert) VoteSigs() map[VoteSignature]IDSet {
	return nvc.voteSigs
}

func (nvc NewViewCert) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("NVC{ anchor: %s, view: %d",
		nvc.anchor.SmallString(), nvc.view))
	if len(nvc.qscs) > 0 {
		var sortedIDs []ID
		for id := range nvc.qscs {
			sortedIDs = append(sortedIDs, id)
		}
		sort.Slice(sortedIDs, func(i, j int) bool {
			return sortedIDs[i] < sortedIDs[j]
		})
		sb.WriteString(fmt.Sprintf(", qscs: ["))
		for i, id := range sortedIDs {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%d", id))
		}
		sb.WriteString("]")
	}
	if len(nvc.voteSigs) > 0 {
		var sortedVoteSigs []VoteSignature
		for voteSig := range nvc.voteSigs {
			sortedVoteSigs = append(sortedVoteSigs, voteSig)
		}
		sort.Slice(sortedVoteSigs, func(i, j int) bool {
			return sortedVoteSigs[i].String() < sortedVoteSigs[j].String()
		})

		sb.WriteString(", voteSigs: { ")
		firstEntry := true
		for _, voteSig := range sortedVoteSigs {
			idSet := nvc.voteSigs[voteSig]
			if !firstEntry {
				sb.WriteString("; ")
			}
			sb.WriteString(voteSig.String())
			sb.WriteString(": [")
			_ = writeParticipants(&sb, idSet)
			sb.WriteString("]")
			firstEntry = false
		}
		sb.WriteString(" }")
	}

	sb.WriteString(" }")
	return sb.String()
}

type QuorumSeenCert struct {
	signature QuorumSignature
	metadata  map[ID]IDSet
	view      View
	hash      Hash
}

func NewQuorumSeenCert(signature QuorumSignature, metadata map[ID]IDSet, view View,
	hash Hash) QuorumSeenCert {
	return QuorumSeenCert{
		signature: signature,
		metadata:  metadata,
		view:      view,
		hash:      hash,
	}
}

func (qsc QuorumSeenCert) Signature() QuorumSignature {
	return qsc.signature
}

func (qsc QuorumSeenCert) Metadata() map[ID]IDSet {
	return qsc.metadata
}

func (qsc QuorumSeenCert) View() View {
	return qsc.view
}

func (qsc QuorumSeenCert) BlockHash() Hash {
	return qsc.hash
}

func (qsc QuorumSeenCert) String() string {
	var sb strings.Builder

	var sortedKeys []ID
	for id := range qsc.metadata {
		sortedKeys = append(sortedKeys, id)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i] < sortedKeys[j]
	})

	firstEntry := true
	for _, id := range sortedKeys {
		idSet := qsc.metadata[id]
		if !firstEntry {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%d: [", id))
		_ = writeParticipants(&sb, idSet)
		sb.WriteString("]")
		firstEntry = false
	}

	return fmt.Sprintf("QSC{ hash: %s, view: %d, metadata: { %s } }", qsc.hash.SmallString(), qsc.view, &sb)
}

func (qsc QuorumSeenCert) ToBytes() []byte {
	buf := qsc.hash[:]
	var viewBuf [8]byte
	binary.LittleEndian.PutUint64(viewBuf[:], uint64(qsc.view))
	buf = append(buf, viewBuf[:]...)
	if qsc.Signature() != nil {
		buf = append(buf, qsc.signature.ToBytes()...)
	}
	keys := make([]ID, 0, len(qsc.metadata))
	for k := range qsc.metadata {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, key := range keys {
		var keyBuf [4]byte
		binary.LittleEndian.PutUint32(keyBuf[:], uint32(key))
		buf = append(buf, keyBuf[:]...)
		value := qsc.metadata[key]
		buf = append(buf, value.ToBytes()...)
	}

	return buf
}

func (qsc QuorumSeenCert) Equals(other QuorumSeenCert) bool {
	if qsc.view != other.view {
		return false
	}
	if qsc.hash != other.hash {
		return false
	}
	if !reflect.DeepEqual(qsc.metadata, other.metadata) {
		return false
	}
	if qsc.signature == nil || other.signature == nil {
		return qsc.signature == other.signature
	}
	return bytes.Equal(qsc.signature.ToBytes(), other.signature.ToBytes())
}

type SeenCert struct {
	signature QuorumSignature
	voter     ID
	blockHash Hash
}

func NewSeenCert(signature QuorumSignature, blockHash Hash, voter ID) SeenCert {
	return SeenCert{
		signature: signature,
		voter:     voter,
		blockHash: blockHash,
	}
}

func (sc SeenCert) Signature() QuorumSignature {
	return sc.signature
}

func (sc SeenCert) Voter() ID {
	return sc.voter
}

func (sc SeenCert) BlockHash() Hash {
	return sc.blockHash
}

func (sc SeenCert) ToBytes() []byte {
	b := sc.signature.ToBytes()
	b = append(b, sc.blockHash[:]...)
	b = append(b, sc.voter.ToBytes()...)
	return b
}

type SeenPartialCert struct {
	signer    ID
	signature QuorumSignature
	voter     ID
	blockHash Hash
	verified  bool
}

func (spc *SeenPartialCert) IsVerified() bool {
	return spc.verified
}

func (spc *SeenPartialCert) SetVerified(verified bool) {
	spc.verified = verified
}

func NewSeenPartialCert(signature QuorumSignature,
	blockHash Hash, voter ID) SeenPartialCert {
	var signer ID
	signature.Participants().RangeWhile(func(i ID) bool {
		signer = i
		return false
	})
	return SeenPartialCert{signer, signature,
		voter, blockHash, false}
}

func (spc *SeenPartialCert) Signer() ID {
	return spc.signer
}

func (spc *SeenPartialCert) Signature() QuorumSignature {
	return spc.signature
}

func (spc *SeenPartialCert) Voter() ID {
	return spc.voter
}

func (spc *SeenPartialCert) BlockHash() Hash {
	return spc.blockHash
}

func (spc *SeenPartialCert) ToBytes() []byte {
	b := append(spc.blockHash[:], spc.voter.ToBytes()...)
	return b
}

type Cert interface {
	ToBytes
	Signature() QuorumSignature
	BlockHash() Hash
	View() View
	String() string
}

var _ fmt.Stringer = (*AggregateQC)(nil)

func writeParticipants(wr io.Writer, participants IDSet) (err error) {
	participants.RangeWhile(func(id ID) bool {
		_, err = fmt.Fprintf(wr, "%d ", id)
		return err == nil
	})
	return err
}

// ReplicaInfo holds information about a replica.
type ReplicaInfo struct {
	ID       ID
	Address  string
	PubKey   PublicKey
	Location string
	Metadata map[string]string
}
