package client

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/info"
)

// Strategy is the means by which the server to use as a remote should
// be selected.
type Strategy int

const (
	// StrategyInvalid indicates any strategy that is unsupported
	// or returned when no strategy is applicable.
	StrategyInvalid = iota

	// StrategyOrderedList is a sequential list of servers: if the
	// first server cannot be reached, the next is used. The
	// client will proceed in this manner until the list of
	// servers is exhausted, and then an error is returned.
	StrategyOrderedList
)

var strategyStrings = map[string]Strategy{
	"ordered_list": StrategyOrderedList,
}

// StrategyFromString takes a string describing a
func StrategyFromString(s string) Strategy {
	s = strings.TrimSpace(strings.ToLower(s))
	strategy, ok := strategyStrings[s]
	if !ok {
		return StrategyInvalid
	}
	return strategy
}

// NewGroup will use the collection of remotes specified with the
// given strategy.
func NewGroup(remotes []string, tlsConfig *tls.Config, strategy Strategy) (Remote, error) {
	var servers = make([]*server, len(remotes))
	for i := range remotes {
		u, err := normalizeURL(remotes[i])
		if err != nil {
			return nil, err
		}
		servers[i] = newServer(u, tlsConfig)
	}

	switch strategy {
	case StrategyOrderedList:
		return newOrdererdListGroup(servers)
	default:
		return nil, errors.New("unrecognised strategy")
	}
}

type orderedListGroup struct {
	remotes []*server
	// reqModifier is the modifier applied to every member so that
	// the same request decoration (custom headers, signing material,
	// etc.) is used on each candidate address.
	reqModifier func(*http.Request, []byte)
}

func (g *orderedListGroup) Hosts() []string {
	var hosts = make([]string, 0, len(g.remotes))
	for _, srv := range g.remotes {
		srvHosts := srv.Hosts()
		hosts = append(hosts, srvHosts[0])
	}
	return hosts
}

func (g *orderedListGroup) SetRequestTimeout(timeout time.Duration) {
	for _, srv := range g.remotes {
		srv.SetRequestTimeout(timeout)
	}
}

func (g *orderedListGroup) SetProxy(proxy func(*http.Request) (*url.URL, error)) {
	for _, srv := range g.remotes {
		srv.SetProxy(proxy)
	}
}

func newOrdererdListGroup(remotes []*server) (Remote, error) {
	return &orderedListGroup{
		remotes: remotes,
	}, nil
}

// orderedFailover runs op against the group members in configuration
// order. The first candidate that returns a valid result stops the
// failover. When every candidate fails the error from the last
// attempted remote is returned so the caller keeps the most recent
// diagnostic information.
func orderedFailover[T any](remotes []*server, op func(*server) (T, error)) (T, error) {
	var zero T
	var lastErr error
	for _, srv := range remotes {
		result, err := op(srv)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return zero, errors.New("no remote servers configured")
	}
	return zero, lastErr
}

// AuthSign performs the authenticated signing request. The
// authenticated request body (token, timestamp and inner request) is
// built a single time and then sent unchanged to the "authsign"
// endpoint of each candidate, in configuration order.
func (g *orderedListGroup) AuthSign(req, id []byte, provider auth.Provider) ([]byte, error) {
	jsonData, err := newAuthenticatedRequestBody(req, id, provider)
	if err != nil {
		return nil, err
	}
	return orderedFailover(g.remotes, func(srv *server) ([]byte, error) {
		return srv.sendAuthenticatedRequest(jsonData, "sign")
	})
}

// Sign sends the same signing request body to the "sign" endpoint of
// each candidate, in configuration order.
func (g *orderedListGroup) Sign(jsonData []byte) ([]byte, error) {
	return orderedFailover(g.remotes, func(srv *server) ([]byte, error) {
		return srv.Sign(jsonData)
	})
}

// Info sends the same info request body to the "info" endpoint of each
// candidate, in configuration order.
func (g *orderedListGroup) Info(jsonData []byte) (*info.Resp, error) {
	return orderedFailover(g.remotes, func(srv *server) (*info.Resp, error) {
		return srv.Info(jsonData)
	})
}

// SetReqModifier propagates the request modifier to every member of the
// group. Each member invokes the modifier a single time per request it
// sends, so the identical decoration is applied to every candidate
// address tried during failover.
func (g *orderedListGroup) SetReqModifier(mod func(*http.Request, []byte)) {
	g.reqModifier = mod
	for _, srv := range g.remotes {
		srv.SetReqModifier(mod)
	}
}
