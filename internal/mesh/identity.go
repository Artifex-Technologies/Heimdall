// Package mesh shares alerts between the Heimdall instances one owner runs on several computers (Phase 3's mesh half,
// docs/MESH.md). It is deliberately small, because a mesh is a way into a computer and "Tailworm" (October 2026) showed how
// mesh features become holes:
//
//   - One thing only: a peer may POST alert summaries to /mesh/v1/alerts. No shell, no file serving, no port forwarding, no
//     relay, no commands, no configuration pushed. A received alert is shown, never acted on: it goes to the alert log and
//     the API, not to containment or quarantine.
//   - Owner-enrolled peers only: each instance has an ed25519 key; the owner enrols a peer by its fingerprint and address on
//     every computer (/etc/heimdall/mesh-peers.json, root's file). There is no coordination server to steal or trick.
//   - Mutual TLS 1.3: both sides present their key; a connection whose key is not enrolled is cut in the handshake.
//   - Off by default: no listener without mesh_listen, nothing sent without an enrolled peer.
package mesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is this instance's key.
type Identity struct {
	Key         ed25519.PrivateKey
	Fingerprint string
}

// Fingerprint names a public key: "hm1-" and the first 32 base32 characters of its SHA-256 (160 bits). The owner compares it
// when enrolling, so it is short enough to read aloud and long enough that nobody can make a key that matches it.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "hm1-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))[:32]
}

// LoadOrCreate reads the key in dir (key.pem, 0600) or makes one. The public fingerprint is also written to dir/fingerprint
// (0644) so `heimdalld mesh id` can show it to any account.
func LoadOrCreate(dir string) (Identity, error) {
	path := filepath.Join(dir, "key.pem")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "PRIVATE KEY" {
			return Identity{}, errors.New(path + " is not a key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return Identity{}, err
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return Identity{}, errors.New(path + " is not an ed25519 key")
		}
		return Identity{Key: priv, Fingerprint: Fingerprint(priv.Public().(ed25519.PublicKey))}, nil
	} else if !os.IsNotExist(err) {
		return Identity{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Identity{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Identity{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Identity{}, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return Identity{}, err
	}
	if err := f.Close(); err != nil {
		return Identity{}, err
	}
	id := Identity{Key: priv, Fingerprint: Fingerprint(pub)}
	_ = os.WriteFile(filepath.Join(dir, "fingerprint"), []byte(id.Fingerprint+"\n"), 0o644)
	return id, nil
}

// certificate is a self-signed certificate for the key. Its names and dates mean nothing to a peer: only the key is checked.
func (id Identity) certificate() (tls.Certificate, error) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.Key.Public(), id.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.Key}, nil
}

// peerFingerprint is the fingerprint of the key in a presented certificate (ed25519 only).
func peerFingerprint(raw [][]byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("no certificate")
	}
	c, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return "", err
	}
	pub, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("not an ed25519 key")
	}
	return Fingerprint(pub), nil
}
