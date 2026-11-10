// Command meshnode runs the Go daemon's mesh (internal/mesh) on its own, so the Rust port's mesh can be proved against it
// over real loopback TLS (rust/heimdall/tests/mesh.rs): the same identity files, enrolment, handshake and alert lines.
//
//	meshnode id DIR
//	    LoadOrCreate the identity in DIR; print its fingerprint.
//	meshnode run --dir DIR --peers FILE [--listen IP:PORT] [--min SEVERITY]
//	    A Node: alert lines on stdin are local alerts (sent to the peers); alerts received from peers are printed as lines
//	    on stdout. Ends on SIGTERM or when stdin says "quit".
//	meshnode post --dir DIR --fp FINGERPRINT --addr IP:PORT [--path P] [--method M] BODYFILE...
//	    One request per body file, as an enrolled (or not) peer would send it; prints the status, or "error: ..." when the
//	    connection or handshake failed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/mesh"
)

type discard struct{}

func (discard) Write(alert.Alert) error { return nil }

type printer struct{ mu sync.Mutex }

func (p *printer) Write(a alert.Alert) error {
	b, err := json.Marshal(a)
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Println(string(b))
	return err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: meshnode id|run|post ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "id":
		id, err := mesh.LoadOrCreate(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(id.Fingerprint)
	case "run":
		os.Exit(run(os.Args[2:]))
	case "post":
		os.Exit(post(os.Args[2:]))
	default:
		os.Exit(2)
	}
}

func run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", "", "")
	peers := fs.String("peers", "", "")
	listen := fs.String("listen", "", "")
	min := fs.String("min", "warning", "")
	fs.Parse(args)
	id, err := mesh.LoadOrCreate(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	n := &mesh.Node{ID: id, PeersPath: *peers, Listen: *listen, Next: discard{}, Out: &printer{}, MinSeverity: detect.Severity(*min)}
	if err := n.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mesh off:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "ready")
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if sc.Text() == "quit" {
				stop()
				return
			}
			var a alert.Alert
			if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
				fmt.Fprintln(os.Stderr, "bad alert line:", err)
				continue
			}
			n.Write(a)
		}
	}()
	<-ctx.Done()
	return 0
}

func post(args []string) int {
	fs := flag.NewFlagSet("post", flag.ExitOnError)
	dir := fs.String("dir", "", "")
	fp := fs.String("fp", "", "")
	addr := fs.String("addr", "", "")
	path := fs.String("path", mesh.Path, "")
	method := fs.String("method", "POST", "")
	fs.Parse(args)
	id, err := mesh.LoadOrCreate(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cert, err := certificate(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// the mesh's own client settings (internal/mesh tlsConfig, for one enrolled peer)
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pub, ok := c.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("not an ed25519 key")
			}
			if got := mesh.Fingerprint(pub); got != *fp {
				return fmt.Errorf("peer key %s is not the enrolled %s", got, *fp)
			}
			return nil
		}}
	for _, f := range fs.Args() {
		body, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
		req, _ := http.NewRequest(*method, "https://"+*addr+*path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Println(resp.StatusCode)
	}
	return 0
}

// certificate is internal/mesh's: a self-signed certificate for the key; only the key counts.
func certificate(id mesh.Identity) (tls.Certificate, error) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.Key.Public(), id.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.Key}, nil
}
