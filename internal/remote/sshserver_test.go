package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server used to exercise the client code in
// remote.go. It accepts publickey auth for a single authorized public key,
// supports "session" channels with exec/shell requests (run via /bin/sh -c),
// and the "sftp" subsystem backed by github.com/pkg/sftp rooted at rootDir.
type testServer struct {
	ln          net.Listener
	cfg         *ssh.ServerConfig
	hostSigner  ssh.Signer
	rootDir     string
	wg          sync.WaitGroup
	mu          sync.Mutex
	closed      bool
	denySFTP    bool // if true, reject the sftp subsystem request
	denySession bool // if true, reject session channels
	denyPTY     bool // if true, reject pty-req requests

	// sftpFault, when non-empty, serves a custom request-based SFTP server that
	// injects a failure: "write" (WriteAt errors), "setstat" (Setstat/chmod
	// errors), or "read" (ReadAt errors). Used to cover the WriteFile/ReadFile
	// error branches that a healthy server never triggers.
	sftpFault string
}

// genSigner creates a fresh ed25519 ssh.Signer.
func genSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// writePEMKey marshals an ed25519 private key signer to a PKCS8 PEM file and
// returns the signer plus the file path.
func writeKeyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := writeTemp(t, "id_ed25519", pemBytes, 0600)
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, path
}

// newTestServer starts an SSH server on 127.0.0.1:0 that accepts the supplied
// authorized client public key. rootDir is the directory the SFTP subsystem is
// rooted at. The server is shut down via t.Cleanup.
func newTestServer(t *testing.T, authorized ssh.PublicKey, rootDir string) *testServer {
	t.Helper()

	hostSigner := genSigner(t)
	authorizedBytes := authorized.Marshal()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorizedBytes) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &testServer{
		ln:         ln,
		cfg:        cfg,
		hostSigner: hostSigner,
		rootDir:    rootDir,
	}

	s.wg.Add(1)
	go s.acceptLoop()

	t.Cleanup(func() { s.Close() })
	return s
}

func (s *testServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.ln.Close()
	s.wg.Wait()
}

func (s *testServer) addr() string { return s.ln.Addr().String() }

func (s *testServer) host() string {
	h, _, _ := net.SplitHostPort(s.ln.Addr().String())
	return h
}

func (s *testServer) port() int {
	_, p, _ := net.SplitHostPort(s.ln.Addr().String())
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

func (s *testServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *testServer) handleConn(conn net.Conn) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		if s.denySession {
			newChan.Reject(ssh.Prohibited, "sessions denied")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ch, requests)
		}()
	}
}

func (s *testServer) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "pty-req", "shell", "env":
			// Accept PTY/shell/env so InteractiveSession works; shell runs nothing.
			// denyPTY rejects pty-req so RequestPty errors on the client side.
			ok := !(req.Type == "pty-req" && s.denyPTY)
			if req.WantReply {
				req.Reply(ok, nil)
			}
			if req.Type == "shell" {
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				return
			}
		case "exec":
			cmd := parseExecPayload(req.Payload)
			if req.WantReply {
				req.Reply(true, nil)
			}
			s.runExec(ch, cmd)
			return
		case "subsystem":
			name := parseExecPayload(req.Payload)
			if name == "sftp" && !s.denySFTP {
				if req.WantReply {
					req.Reply(true, nil)
				}
				s.serveSFTP(ch)
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// parseExecPayload extracts the string from an exec/subsystem request payload,
// which is a 4-byte big-endian length followed by the command/name.
func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if 4+n > len(payload) {
		return ""
	}
	return string(payload[4 : 4+n])
}

func (s *testServer) runExec(ch ssh.Channel, command string) {
	cmd := exec.Command("/bin/sh", "-c", command)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var status uint32
	if err := cmd.Start(); err != nil {
		status = 127
	} else {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(ch, stdout) }()
		go func() { defer wg.Done(); io.Copy(ch.Stderr(), stderr) }()
		wg.Wait()
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				status = uint32(exitErr.ExitCode())
			} else {
				status = 1
			}
		}
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	ch.Close()
}

func (s *testServer) serveSFTP(ch ssh.Channel) {
	if s.sftpFault != "" {
		s.serveFaultySFTP(ch)
		return
	}
	server, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(s.rootDir))
	if err != nil {
		ch.Close()
		return
	}
	server.Serve()
	server.Close()
	ch.Close()
}

// serveFaultySFTP serves a request-based SFTP server whose handlers inject a
// failure selected by s.sftpFault.
func (s *testServer) serveFaultySFTP(ch ssh.Channel) {
	h := &faultyHandler{fault: s.sftpFault}
	server := sftp.NewRequestServer(ch, sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	server.Serve()
	server.Close()
	ch.Close()
}

// faultyHandler implements the pkg/sftp request handler interfaces and injects
// errors based on fault.
type faultyHandler struct{ fault string }

type errWriterAt struct{ fail bool }

func (w *errWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if w.fail {
		return 0, fmt.Errorf("injected write failure")
	}
	return len(p), nil
}

type errReaderAt struct{}

func (errReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return 0, fmt.Errorf("injected read failure")
}

func (h *faultyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	// Open/Put succeeds; WriteAt fails only when fault == "write".
	return &errWriterAt{fail: h.fault == "write"}, nil
}

func (h *faultyHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	return errReaderAt{}, nil
}

func (h *faultyHandler) Filecmd(r *sftp.Request) error {
	// MkdirAll issues Mkdir requests which must succeed; only Setstat (chmod)
	// fails when fault == "setstat".
	if r.Method == "Setstat" && h.fault == "setstat" {
		return fmt.Errorf("injected setstat failure")
	}
	return nil
}

func (h *faultyHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return nil, fmt.Errorf("not supported")
}
