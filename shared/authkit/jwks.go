package authkit

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// Ed25519 / OKP
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type JWKSProvider struct {
	URL     string
	AlgHint string // "RS256" | "EdDSA"

	mu      sync.RWMutex
	keys    map[string]any // kid -> *rsa.PublicKey or ed25519.PublicKey
	client  *http.Client
	etag    string
	lastErr error
}

func NewJWKSProvider(url, alg string) *JWKSProvider {
	return &JWKSProvider{
		URL:     url,
		AlgHint: alg,
		client:  &http.Client{Timeout: 5 * time.Second},
		keys:    make(map[string]any),
	}
}

func (p *JWKSProvider) Start(ctx context.Context, every time.Duration) {
	// initial fetch
	_ = p.Fetch(ctx)
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = p.Fetch(ctx)
			}
		}
	}()
}

func (p *JWKSProvider) Fetch(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", p.URL, nil)
	if p.etag != "" {
		req.Header.Set("If-None-Match", p.etag)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != 200 {
		p.mu.Lock()
		p.lastErr = fmt.Errorf("jwks http %d", resp.StatusCode)
		p.mu.Unlock()
		return p.lastErr
	}
	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}
	if et := resp.Header.Get("ETag"); et != "" {
		p.etag = et
	}

	parsed := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		switch p.AlgHint {
		case "RS256":
			pub, err := parseRSAPublic(k.N, k.E)
			if err == nil && k.Kid != "" {
				parsed[k.Kid] = pub
			}
		case "EdDSA":
			pub, err := parseEd25519Public(k.X)
			if err == nil && k.Kid != "" {
				parsed[k.Kid] = pub
			}
		}
	}
	if len(parsed) == 0 {
		p.mu.Lock()
		p.lastErr = errors.New("no usable keys")
		p.mu.Unlock()
		return p.lastErr
	}

	p.mu.Lock()
	p.keys = parsed
	p.lastErr = nil
	p.mu.Unlock()
	return nil
}

func (p *JWKSProvider) Get(kid string) (any, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, ok := p.keys[kid]
	return v, ok
}

// --- helpers to parse keys (base64url) ---

// (Tiny decoders to avoid extra deps.)
func parseRSAPublic(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("rsa N decode: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("rsa E decode: %w", err)
	}
	// E is big-endian integer in bytes (e.g., "AQAB" -> 65537)
	if len(eb) == 0 {
		return nil, errors.New("rsa E empty")
	}
	e := 0
	for _, b := range eb {
		e = (e << 8) | int(b)
	}
	if e <= 1 {
		return nil, fmt.Errorf("rsa E invalid: %d", e)
	}

	n := new(big.Int).SetBytes(nb)
	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseEd25519Public(xB64 string) (ed25519.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("ed25519 X decode: %w", err)
	}
	if len(xb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 size invalid: %d", len(xb))
	}
	return ed25519.PublicKey(xb), nil
}
