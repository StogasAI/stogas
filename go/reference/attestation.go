package reference

import (
	"bytes"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
)

// Independent quote-batch, session-evidence and node-identity decoding. Gateway
// tests use it to check what the Rust producer emits for each channel.

const (
	ReportBytes    = 1184
	MediaType      = "application/vnd.stogas.native-tls.v1"
	maxBatchLeaves = 1024
	maxProofHashes = 10
	batchDomain    = "stogas.quote-batch.v1\x00"
	tlsLeafDomain  = "stogas.native-tls.v1\x00"
	e2eeLeafDomain = "stogas.e2ee-session.v1\x00"
	leafPrefix     = 0
	interiorPrefix = 1
)

func leaf(domain string, environment byte, fields ...[32]byte) [64]byte {
	h := sha512.New()
	h.Write([]byte{leafPrefix})
	h.Write([]byte(domain))
	h.Write([]byte{environment})
	for _, field := range fields {
		h.Write(field[:])
	}
	return [64]byte(h.Sum(nil))
}

// TLSLeaf binds a boot, the client's challenge and the certificate key.
func TLSLeaf(environment byte, boot, challenge, signerSPKI [32]byte) [64]byte {
	return leaf(tlsLeafDomain, environment, boot, challenge, signerSPKI)
}

// E2EELeaf binds a boot and an encrypted setup transcript.
func E2EELeaf(environment byte, boot, transcript [32]byte) [64]byte {
	return leaf(e2eeLeafDomain, environment, boot, transcript)
}

func parent(left, right [64]byte) [64]byte {
	return sha512.Sum512(append(append([]byte{interiorPrefix}, left[:]...), right[:]...))
}

// VerifyBatchProof checks RFC 9162 inclusion of one leaf in SNP report data.
func VerifyBatchProof(leaf [64]byte, proof []byte, reportData [64]byte) error {
	if len(proof) < 4 || (len(proof)-4)%64 != 0 || len(proof) > 4+maxProofHashes*64 {
		return errors.New("invalid proof length")
	}
	count, index := binary.BigEndian.Uint16(proof), binary.BigEndian.Uint16(proof[2:])
	if count == 0 || count > maxBatchLeaves || index >= count || depth(count, index) != (len(proof)-4)/64 {
		return errors.New("invalid proof shape")
	}
	root, position, last := leaf, uint64(index), uint64(count)-1
	for offset := 4; offset < len(proof); offset += 64 {
		sibling := [64]byte(proof[offset : offset+64])
		if position&1 != 0 || position == last {
			root = parent(sibling, root)
			for position != 0 && position&1 == 0 {
				position >>= 1
				last >>= 1
			}
		} else {
			root = parent(root, sibling)
		}
		position >>= 1
		last >>= 1
	}
	data := append([]byte(batchDomain), byte(count>>8), byte(count))
	if last != 0 || sha512.Sum512(append(data, root[:]...)) != reportData {
		return errors.New("proof does not bind this leaf")
	}
	return nil
}

func depth(count, index uint16) int {
	levels := 0
	for count > 1 {
		split := uint16(1) << (bits.Len16(count-1) - 1)
		if index < split {
			count = split
		} else {
			index -= split
			count -= split
		}
		levels++
	}
	return levels
}

// SessionEvidence is the decoded payload of a certificate or encrypted setup.
type SessionEvidence struct {
	Report, Proof, Document, Inclusion []byte
}

// ParseSessionEvidence decodes report, proof and the two length-prefixed boot fields.
func ParseSessionEvidence(payload []byte) (SessionEvidence, error) {
	if len(payload) < ReportBytes+2 {
		return SessionEvidence{}, errors.New("truncated evidence")
	}
	evidence := SessionEvidence{Report: payload[:ReportBytes]}
	payload = payload[ReportBytes:]
	length := int(binary.BigEndian.Uint16(payload))
	if len(payload) < 2+length {
		return SessionEvidence{}, errors.New("truncated proof")
	}
	evidence.Proof, payload = payload[2:2+length], payload[2+length:]
	for _, field := range []*[]byte{&evidence.Document, &evidence.Inclusion} {
		if len(payload) < 4 || len(payload)-4 < int(binary.BigEndian.Uint32(payload)) {
			return SessionEvidence{}, errors.New("truncated boot field")
		}
		size := 4 + int(binary.BigEndian.Uint32(payload))
		*field, payload = payload[4:size], payload[size:]
	}
	if len(payload) != 0 {
		return SessionEvidence{}, errors.New("trailing evidence bytes")
	}
	return evidence, nil
}

// ParseCertificateExtension decodes the CMW record carried in a native certificate.
func ParseCertificateExtension(value []byte) (SessionEvidence, error) {
	var cmw []byte
	if rest, err := asn1.Unmarshal(value, &cmw); err != nil || len(rest) != 0 {
		return SessionEvidence{}, errors.New("invalid CMW octet string")
	}
	prefix := append([]byte{0x82, 0x78, byte(len(MediaType))}, MediaType...)
	if !bytes.HasPrefix(cmw, prefix) || len(cmw) < len(prefix)+3 || cmw[len(prefix)] != 0x59 ||
		int(binary.BigEndian.Uint16(cmw[len(prefix)+1:])) != len(cmw)-len(prefix)-3 {
		return SessionEvidence{}, errors.New("invalid CMW record")
	}
	return ParseSessionEvidence(cmw[len(prefix)+3:])
}

var nodeAdjectives = [...]string{
	"amber", "bright", "clear", "direct", "early", "firm", "green", "high",
	"inner", "level", "prime", "quiet", "ready", "solid", "steady", "true",
}

var nodeNouns = [...]string{
	"anchor", "beacon", "bridge", "forge", "guard", "harbor", "index", "keystone",
	"ledger", "marker", "nexus", "pivot", "relay", "signal", "vector", "watch",
}

// SNPNodeID names a guest from its report's REPORT_ID.
func SNPNodeID(reportID [32]byte) string {
	return nodeAdjectives[reportID[0]>>4] + "-" + nodeNouns[reportID[0]&15] + "-" + hex.EncodeToString(reportID[:])
}
