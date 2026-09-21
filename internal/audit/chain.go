package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// genesis is the prev_hash of every session's first row.
var genesis = sha256.Sum256([]byte("agentvault:v1"))

// chain owns the hash-chain state for one open session. NOT goroutine
// safe by design: only the single audit writer goroutine may touch it.
type chain struct {
	prev [32]byte
	seq  int64
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newChain() (*chain, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &chain{prev: genesis, seq: 0, priv: priv, pub: pub}, nil
}

// append computes the row hash:
//
//	sha256(prev || payload || verdict || rule_name || ts)
//
// advancing the chain. Returns (seq, prevHash, rowHash) as fresh slices.
// rule_name is included so re-attributing a decision to an
// innocent-looking rule is tamper-evident (extends SPEC §3.4).
func (c *chain) append(payload []byte, verdict, rule, ts string) (seq int64, prev, row []byte) {
	// Copy prev BEFORE mutating c.prev: slicing the array field would
	// alias it, and the mutation below would corrupt the stored value.
	prev = make([]byte, 32)
	copy(prev, c.prev[:])
	seq = c.seq

	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	h.Write([]byte(verdict))
	h.Write([]byte(rule))
	h.Write([]byte(ts))
	row = h.Sum(nil) // fresh 32-byte slice

	copy(c.prev[:], row)
	c.seq++
	return seq, prev, row
}

// head returns the current chain tip (genesis when no events yet).
func (c *chain) head() []byte { out := c.prev; return out[:] }

// sign signs the chain head with the session key.
func (c *chain) sign() (sig []byte) {
	return ed25519.Sign(c.priv, c.head())
}

// destroy zeroes the private key. After this, no new rows can ever be
// validly appended under this session's identity.
func (c *chain) destroy() {
	for i := range c.priv {
		c.priv[i] = 0
	}
	c.priv = nil
}

// recompute walks stored rows and returns the derived chain head.
// Used by Verify. Inputs are the stored fields, in seq order.
func recompute(rows []storedRow) ([]byte, error) {
	prev := genesis
	for _, r := range rows {
		h := sha256.New()
		h.Write(prev[:])
		h.Write([]byte(r.payload))
		h.Write([]byte(r.verdict))
		h.Write([]byte(r.ruleName))
		h.Write([]byte(r.ts))
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		if !equalBytes(sum[:], r.rowHash) {
			return nil, fmt.Errorf("row seq=%d id=%s: hash mismatch (stored %s, computed %s)",
				r.seq, r.id, hex.EncodeToString(r.rowHash), hex.EncodeToString(sum[:]))
		}
		if !equalBytes(r.prevHash, prev[:]) {
			return nil, fmt.Errorf("row seq=%d id=%s: prev_hash chain break", r.seq, r.id)
		}
		prev = sum
	}
	return prev[:], nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// storedRow is the subset of an events row needed to verify the chain.
type storedRow struct {
	id       string
	seq      int64
	ts       string
	payload  string
	verdict  string
	ruleName string
	prevHash []byte
	rowHash  []byte
}

// verifySignature checks headSig over headHash with pub.
func verifySignature(pub, headHash, headSig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), headHash, headSig)
}

// policyHashOf computes the sha256 of the raw policy file bytes,
// stored on the session row so audits are attributable to an exact config.
func policyHashOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
