package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type jwkAny struct {
	Kty string `json:"kty"`           // "RSA" or "OKP"
	Use string `json:"use,omitempty"` // expect "sig"
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"` // e.g., "RS256" or "EdDSA"
	// RSA
	N string `json:"n,omitempty"` // base64url modulus
	E string `json:"e,omitempty"` // base64url exponent
	// OKP
	Crv string `json:"crv,omitempty"` // "Ed25519"
	X   string `json:"x,omitempty"`   // base64url public key
}
type jwksDoc struct {
	Keys []jwkAny `json:"keys"`
}

// HTTPMultiJWKSProvider caches RSA and Ed25519 keys from a JWKS URL.
type HTTPMultiJWKSProvider struct {
	URL        string
	TTL        time.Duration
	HTTPClient *http.Client

	mu        sync.RWMutex
	lastFetch time.Time
	rsaKeys   map[string]*rsa.PublicKey
	edKeys    map[string]ed25519.PublicKey
}

func NewHTTPMultiJWKSProvider(url string, ttl time.Duration) *HTTPMultiJWKSProvider {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &HTTPMultiJWKSProvider{
		URL:        url,
		TTL:        ttl,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		rsaKeys:    make(map[string]*rsa.PublicKey),
		edKeys:     make(map[string]ed25519.PublicKey),
	}
}

func (p *HTTPMultiJWKSProvider) GetRSA(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	pub, fresh := p.getRSACached(kid)
	if pub != nil && fresh {
		return pub, nil
	}
	if err := p.refresh(ctx); err != nil {
		// fallback to stale cache if present
		if pub, _ := p.getRSACached(kid); pub != nil {
			return pub, nil
		}
		return nil, err
	}
	pub, _ = p.getRSACached(kid)
	if pub == nil {
		return nil, errors.New("jwks: rsa kid not found")
	}
	return pub, nil
}

func (p *HTTPMultiJWKSProvider) GetEd25519(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	pub, fresh := p.getEdCached(kid)
	if pub != nil && fresh {
		return pub, nil
	}
	if err := p.refresh(ctx); err != nil {
		if pub, _ := p.getEdCached(kid); pub != nil {
			return pub, nil
		}
		return nil, err
	}
	pub, _ = p.getEdCached(kid)
	if pub == nil {
		return nil, errors.New("jwks: ed25519 kid not found")
	}
	return pub, nil
}

func (p *HTTPMultiJWKSProvider) getRSACached(kid string) (*rsa.PublicKey, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pub := p.rsaKeys[kid]
	fresh := time.Since(p.lastFetch) < p.TTL
	return pub, fresh
}
func (p *HTTPMultiJWKSProvider) getEdCached(kid string) (ed25519.PublicKey, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pub, ok := p.edKeys[kid]
	if !ok {
		return nil, false
	}
	fresh := time.Since(p.lastFetch) < p.TTL
	return pub, fresh
}

func (p *HTTPMultiJWKSProvider) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return err
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("jwks: http status not ok")
	}

	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	newRSA := make(map[string]*rsa.PublicKey)
	newED := make(map[string]ed25519.PublicKey)

	for _, k := range doc.Keys {
		switch strings.ToUpper(k.Kty) {
		case "RSA":
			// accept if alg empty or RS256
			if k.Kid == "" {
				continue
			}
			if k.Alg != "" && !strings.EqualFold(k.Alg, "RS256") {
				continue
			}
			nb, err := b64urlDecode(k.N)
			if err != nil || len(nb) == 0 {
				continue
			}
			eb, err := b64urlDecode(k.E)
			if err != nil || len(eb) == 0 {
				continue
			}
			var e int
			for _, b := range eb {
				e = (e << 8) | int(b)
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
			newRSA[k.Kid] = pub

		case "OKP":
			// Ed25519
			if !strings.EqualFold(k.Crv, "Ed25519") {
				continue
			}
			if k.Kid == "" {
				continue
			}
			if k.Alg != "" && !strings.EqualFold(k.Alg, "EdDSA") {
				continue
			}
			xb, err := b64urlDecode(k.X)
			if err != nil || len(xb) != ed25519.PublicKeySize {
				continue
			}
			newED[k.Kid] = ed25519.PublicKey(xb)
		default:
			// ignore others
		}
	}

	if len(newRSA) == 0 && len(newED) == 0 {
		return errors.New("jwks: no usable keys found")
	}

	p.mu.Lock()
	p.rsaKeys = newRSA
	p.edKeys = newED
	p.lastFetch = time.Now()
	p.mu.Unlock()
	return nil
}
