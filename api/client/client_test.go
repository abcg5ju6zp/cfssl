package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/helpers"
)

var (
	testProvider auth.Provider
	testKey      = "0123456789ABCDEF0123456789ABCDEF"
	testAD       = []byte{1, 2, 3, 4} // IP address 1.2.3.4
)

func TestNewServer(t *testing.T) {
	s := NewServer("1.1.1.1:::123456789")
	if s != nil {
		t.Fatalf("fatal error, server created with too many colons %v", s)
	}

	s2 := NewServer("1.1.1.1:[]")
	if s != nil {
		t.Fatalf("%v", s2)

	}

	_, port, _ := net.SplitHostPort("")
	if port != "" {
		t.Fatalf("%v", port)

	}

	s = NewServer("http://127.0.0.1:8888")
	hosts := s.Hosts()
	if len(hosts) != 1 || hosts[0] != "http://127.0.0.1:8888" {
		t.Fatalf("expected [http://127.0.0.1:8888], but have %v", hosts)
	}

	s = NewServer("http://1.1.1.1:9999")
	hosts = s.Hosts()
	if len(hosts) != 1 || hosts[0] != "http://1.1.1.1:9999" {
		t.Fatalf("expected [http://1.1.1.1:9999], but have %v", hosts)
	}

	s = NewServer("https://1.1.1.1:8080")
	hosts = s.Hosts()
	if len(hosts) != 1 || hosts[0] != "https://1.1.1.1:8080" {
		t.Fatalf("expected [https://1.1.1.1:8080], but have %v", hosts)
	}
}

func TestInvalidPort(t *testing.T) {
	s := NewServer("1.1.1.1:99999999999999999999999999999")
	if s != nil {
		t.Fatalf("%v", s)
	}
}

func TestAuthSign(t *testing.T) {
	s := NewServer(".X")
	testProvider, _ = auth.New(testKey, nil)
	testRequest := []byte(`testing 1 2 3`)
	as, err := s.AuthSign(testRequest, testAD, testProvider)
	if as != nil || err == nil {
		t.Fatal("expected error with auth sign function")
	}
}

func TestDefaultAuthSign(t *testing.T) {
	testProvider, _ = auth.New(testKey, nil)
	s := NewAuthServer(".X", nil, testProvider)
	testRequest := []byte(`testing 1 2 3`)
	as, err := s.Sign(testRequest)
	if as != nil || err == nil {
		t.Fatal("expected error with auth sign function")
	}
}

func TestSign(t *testing.T) {
	s := NewServer(".X")
	sign, err := s.Sign([]byte{5, 5, 5, 5})
	if sign != nil || err == nil {
		t.Fatalf("expected error with sign function")
	}
}

func TestNewMutualTLSServer(t *testing.T) {
	cert, _ := helpers.LoadClientCertificate("../../helpers/testdata/ca.pem", "../../helpers/testdata/ca_key.pem")
	s := NewServerTLS("https://nohost:8888", helpers.CreateTLSConfig(nil, cert))
	if s == nil {
		t.Fatalf("fatal error, empty server")
	}
	_, err := s.Sign([]byte{5, 5, 5, 5})
	if err == nil {
		t.Fatalf("expected error with sign function")
	}
	if !(strings.Contains(err.Error(), "Post")) && !(strings.Contains(err.Error(), "https://nohost:8888/api/v1/cfssl/sign")) && !(strings.Contains(err.Error(), "dial tcp: lookup nohost: no such host")) {
		t.Fatalf("no error message %v", err)
	}
}

func TestNewServerGroup(t *testing.T) {
	s := NewServer("cfssl1.local:8888, cfssl2.local:8888, http://cfssl3.local:8888, http://cfssl4.local:8888")

	ogl, ok := s.(*orderedListGroup)
	if !ok {
		t.Fatalf("expected NewServer to return an ordered group list with a list of servers, instead got a %T = %+v", ogl, ogl)
	}

	if len(ogl.remotes) != 4 {
		t.Fatalf("expected the remote to have four servers, but it has %d", len(ogl.remotes))
	}

	hosts := ogl.Hosts()
	if len(hosts) != 4 {
		t.Fatalf("expected 2 hosts in the group, but have %d", len(hosts))
	}

	if hosts[0] != "http://cfssl1.local:8888" {
		t.Fatalf("expected to see http://cfssl1.local:8888, but saw %s",
			hosts[0])
	}

	if hosts[1] != "http://cfssl2.local:8888" {
		t.Fatalf("expected to see http://cfssl2.local:8888, but saw %s",
			hosts[1])
	}

	if hosts[2] != "http://cfssl3.local:8888" {
		t.Fatalf("expected to see http://cfssl1.local:8888, but saw %s",
			hosts[2])
	}

	if hosts[3] != "http://cfssl4.local:8888" {
		t.Fatalf("expected to see http://cfssl2.local:8888, but saw %s",
			hosts[3])
	}
}

func TestNewTLSServerGroup(t *testing.T) {
	NewTLSServerGroup(t, nil)
}

func TestNewMutualTLSServerGroup(t *testing.T) {
	cert, _ := helpers.LoadClientCertificate("../../helpers/testdata/ca.pem", "../../helpers/testdata/ca_key.pem")
	NewTLSServerGroup(t, cert)
}

func NewTLSServerGroup(t *testing.T, cert *tls.Certificate) {
	s := NewServerTLS("https://cfssl1.local:8888, https://cfssl2.local:8888", helpers.CreateTLSConfig(nil, cert))

	ogl, ok := s.(*orderedListGroup)
	if !ok {
		t.Fatalf("expected NewServer to return an ordered group list with a list of servers, instead got a %T = %+v", ogl, ogl)
	}

	if len(ogl.remotes) != 2 {
		t.Fatalf("expected the remote to have two servers, but it has %d", len(ogl.remotes))
	}

	hosts := ogl.Hosts()
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts in the group, but have %d", len(hosts))
	}

	if hosts[0] != "https://cfssl1.local:8888" {
		t.Fatalf("expected to see https://cfssl1.local:8888, but saw %s",
			hosts[0])
	}

	if hosts[1] != "https://cfssl2.local:8888" {
		t.Fatalf("expected to see https://cfssl2.local:8888, but saw %s",
			hosts[1])
	}
}

func TestNewOGLGroup(t *testing.T) {
	strategy := StrategyFromString("ordered_list")
	if strategy == StrategyInvalid {
		t.Fatal("expected StrategyOrderedList as selected strategy but have StrategyInvalid")
	}

	if strategy != StrategyOrderedList {
		t.Fatalf("expected StrategyOrderedList (%d) but have %d", StrategyOrderedList, strategy)
	}

	rem, err := NewGroup([]string{"ca1.local,", "ca2.local"}, nil, strategy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	ogl, ok := rem.(*orderedListGroup)
	if !ok {
		t.Fatalf("expected to get an orderedListGroup but got %T", rem)
	}

	if len(ogl.remotes) != 2 {
		t.Fatalf("expected two remotes in the ordered group list but have %d", len(ogl.remotes))
	}
}

const testModifierHeader = "X-Cfssl-Test-Modifier"

type recordedRequest struct {
	path   string
	header string
	body   []byte
}

type stubRemote struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func (rec *stubRemote) snapshot() []recordedRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]recordedRequest, len(rec.requests))
	copy(out, rec.requests)
	return out
}

func newStubServer(t *testing.T, reply http.HandlerFunc) (*httptest.Server, *stubRemote) {
	rec := new(stubRemote)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.requests = append(rec.requests, recordedRequest{
			path:   r.URL.Path,
			header: r.Header.Get(testModifierHeader),
			body:   body,
		})
		rec.mu.Unlock()
		reply(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, rec
}

func replySuccessCert(cert string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.NewSuccessResponse(map[string]string{
			"certificate": cert,
		}))
	}
}

func replyFailure(msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, msg, http.StatusInternalServerError)
	}
}

// newTestGroup builds an ordered list group out of the given stub
// servers and installs a request modifier that counts how many times it
// is invoked while tagging each request with a header.
func newTestGroup(t *testing.T, urls []string) (Remote, *int32) {
	g, err := NewGroup(urls, nil, StrategyOrderedList)
	if err != nil {
		t.Fatal(err)
	}
	var modifierCalls int32
	g.SetReqModifier(func(req *http.Request, body []byte) {
		atomic.AddInt32(&modifierCalls, 1)
		req.Header.Set(testModifierHeader, "applied")
	})
	return g, &modifierCalls
}

func assertRecordedOnce(t *testing.T, rec *stubRemote, wantPath string, wantBody []byte) {
	requests := rec.snapshot()
	if len(requests) != 1 {
		t.Fatalf("expected candidate to be tried exactly once, but was tried %d times", len(requests))
	}
	if requests[0].path != wantPath {
		t.Fatalf("expected request to %s, but saw %s", wantPath, requests[0].path)
	}
	if requests[0].header != "applied" {
		t.Fatalf("expected request modifier header on %s, but got %q", wantPath, requests[0].header)
	}
	if !bytes.Equal(requests[0].body, wantBody) {
		t.Fatalf("expected body %s, but got %s", wantBody, requests[0].body)
	}
}

func assertNotTried(t *testing.T, rec *stubRemote) {
	if n := len(rec.snapshot()); n != 0 {
		t.Fatalf("expected candidate not to be tried after a success, but it was tried %d times", n)
	}
}

// TestOrderedGroupSignFailover verifies that a failed first candidate
// causes the group to try the next address in configuration order, that
// each candidate receives the identical request body with the modifier
// applied exactly once, and that later candidates are not tried once a
// valid result has been returned.
func TestOrderedGroupSignFailover(t *testing.T) {
	s1, r1 := newStubServer(t, replyFailure("first-node-failure"))
	s2, r2 := newStubServer(t, replySuccessCert("SECOND-CERT"))
	s3, r3 := newStubServer(t, replySuccessCert("THIRD-CERT"))

	g, modifierCalls := newTestGroup(t, []string{s1.URL, s2.URL, s3.URL})

	payload := []byte(`{"request":"csr","profile":"default"}`)
	cert, err := g.Sign(payload)
	if err != nil {
		t.Fatalf("expected successful failover to second node, got error: %v", err)
	}
	if string(cert) != "SECOND-CERT" {
		t.Fatalf("expected certificate from second node, got %q", cert)
	}

	assertRecordedOnce(t, r1, "/api/v1/cfssl/sign", payload)
	assertRecordedOnce(t, r2, "/api/v1/cfssl/sign", payload)
	assertNotTried(t, r3)

	if n := atomic.LoadInt32(modifierCalls); n != 2 {
		t.Fatalf("expected modifier to run once per attempted candidate (2 times), ran %d times", n)
	}
}

// TestOrderedGroupSignAllFail returns the error from the final
// candidate, preserving its diagnostics, and still contacts every node
// in configuration order.
func TestOrderedGroupSignAllFail(t *testing.T) {
	s1, r1 := newStubServer(t, replyFailure("first-node-failure"))
	s2, r2 := newStubServer(t, replyFailure("second-node-failure"))
	s3, r3 := newStubServer(t, replyFailure("third-node-failure"))

	g, _ := newTestGroup(t, []string{s1.URL, s2.URL, s3.URL})

	_, err := g.Sign([]byte(`{}`))
	if err == nil {
		t.Fatal("expected an error when every candidate fails")
	}
	if !strings.Contains(err.Error(), "third-node-failure") {
		t.Fatalf("expected the last candidate's error, got: %v", err)
	}

	for i, rec := range []*stubRemote{r1, r2, r3} {
		requests := rec.snapshot()
		if len(requests) != 1 {
			t.Fatalf("candidate %d: expected exactly one attempt, got %d", i+1, len(requests))
		}
	}
}

// TestOrderedGroupAuthSign verifies that the authenticated envelope
// (token, timestamp, inner request) is built once and sent unchanged to
// the authsign endpoint of every candidate.
func TestOrderedGroupAuthSign(t *testing.T) {
	s1, r1 := newStubServer(t, replyFailure("first-node-failure"))
	s2, r2 := newStubServer(t, replySuccessCert("AUTH-CERT"))
	s3, r3 := newStubServer(t, replySuccessCert("THIRD-CERT"))

	g, _ := newTestGroup(t, []string{s1.URL, s2.URL, s3.URL})

	provider, err := auth.New(testKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	inner := []byte(`{"request":"csr"}`)
	cert, err := g.AuthSign(inner, testAD, provider)
	if err != nil {
		t.Fatalf("expected successful auth sign failover, got error: %v", err)
	}
	if string(cert) != "AUTH-CERT" {
		t.Fatalf("expected certificate from second node, got %q", cert)
	}

	first := r1.snapshot()
	second := r2.snapshot()
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one request to each of the first two nodes, got %d and %d", len(first), len(second))
	}
	if first[0].path != "/api/v1/cfssl/authsign" || second[0].path != "/api/v1/cfssl/authsign" {
		t.Fatalf("expected both requests to target authsign, got %q and %q", first[0].path, second[0].path)
	}
	if !bytes.Equal(first[0].body, second[0].body) {
		t.Fatalf("expected identical authenticated request body on every candidate")
	}
	if first[0].header != "applied" || second[0].header != "applied" {
		t.Fatal("expected request modifier on every authenticated candidate")
	}
	assertNotTried(t, r3)

	var aReq auth.AuthenticatedRequest
	if err := json.Unmarshal(second[0].body, &aReq); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aReq.Request, inner) {
		t.Fatalf("expected inner request to be preserved, got %s", aReq.Request)
	}
	if !bytes.Equal(aReq.RemoteAddress, testAD) {
		t.Fatalf("expected remote address to be preserved, got %v", aReq.RemoteAddress)
	}
	if aReq.Timestamp == 0 || len(aReq.Token) == 0 {
		t.Fatal("expected timestamp and token in the authenticated request")
	}
}

// TestOrderedGroupInfoFailover applies the same failover semantics to
// info requests: identical body, same endpoint, success stops failover.
func TestOrderedGroupInfoFailover(t *testing.T) {
	s1, r1 := newStubServer(t, replyFailure("first-node-failure"))
	s2, r2 := newStubServer(t, replySuccessInfo)
	s3, r3 := newStubServer(t, replySuccessInfo)

	g, _ := newTestGroup(t, []string{s1.URL, s2.URL, s3.URL})

	payload := []byte(`{"profile":"default"}`)
	resp, err := g.Info(payload)
	if err != nil {
		t.Fatalf("expected successful info failover, got error: %v", err)
	}
	if resp.Certificate != "CA-CERT" {
		t.Fatalf("expected CA certificate from second node, got %q", resp.Certificate)
	}

	assertRecordedOnce(t, r1, "/api/v1/cfssl/info", payload)
	assertRecordedOnce(t, r2, "/api/v1/cfssl/info", payload)
	assertNotTried(t, r3)
}

func replySuccessInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.NewSuccessResponse(map[string]interface{}{
		"certificate": "CA-CERT",
		"usages":      []string{"cert sign"},
		"expiry":      "2030-01-01T00:00:00Z",
	}))
}

// TestOrderedGroupEmpty verifies that a group without members reports a
// diagnostic error instead of a silent (nil, nil) result.
func TestOrderedGroupEmpty(t *testing.T) {
	g, err := NewGroup(nil, nil, StrategyOrderedList)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sign([]byte(`{}`)); err == nil {
		t.Fatal("expected an error when no remote is configured")
	}
}

// TestOrderedGroupSettingsPropagated verifies group level timeout, proxy
// and request modifier settings reach every member.
func TestOrderedGroupSettingsPropagated(t *testing.T) {
	s1, _ := newStubServer(t, replyFailure("x"))
	s2, _ := newStubServer(t, replyFailure("y"))

	g, err := NewGroup([]string{s1.URL, s2.URL}, nil, StrategyOrderedList)
	if err != nil {
		t.Fatal(err)
	}
	ogl, ok := g.(*orderedListGroup)
	if !ok {
		t.Fatalf("expected orderedListGroup, got %T", g)
	}

	timeout := 7 * time.Second
	proxyURL, err := url.Parse("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}
	proxy := http.ProxyURL(proxyURL)
	mod := func(*http.Request, []byte) {}

	g.SetRequestTimeout(timeout)
	g.SetProxy(proxy)
	g.SetReqModifier(mod)

	if ogl.reqModifier == nil {
		t.Fatal("expected group to retain the request modifier")
	}
	for i, srv := range ogl.remotes {
		if srv.RequestTimeout != timeout {
			t.Fatalf("member %d: expected timeout %s, got %s", i, timeout, srv.RequestTimeout)
		}
		if srv.proxy == nil {
			t.Fatalf("member %d: expected proxy to be configured", i)
		}
		if srv.reqModifier == nil {
			t.Fatalf("member %d: expected request modifier to be propagated", i)
		}
	}
}

// TestProxyHonouredWithoutTLS verifies that a configured proxy applies
// to plain HTTP requests (both single remote and group), not only to
// TLS clients.
func TestProxyHonouredWithoutTLS(t *testing.T) {
	proxyTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "proxy-blocked", http.StatusBadGateway)
	}))
	t.Cleanup(proxyTS.Close)

	proxyURL, err := url.Parse(proxyTS.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := http.ProxyURL(proxyURL)

	g, err := NewGroup([]string{"http://first.invalid:9999", "http://second.invalid:9999"}, nil, StrategyOrderedList)
	if err != nil {
		t.Fatal(err)
	}
	g.SetProxy(proxy)
	if _, err := g.Sign([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "proxy-blocked") {
		t.Fatalf("expected proxy diagnostic from group request, got: %v", err)
	}

	s := NewServer("http://single.invalid:9999")
	s.SetProxy(proxy)
	if _, err := s.Sign([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "proxy-blocked") {
		t.Fatalf("expected proxy diagnostic from single remote request, got: %v", err)
	}
}
