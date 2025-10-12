package httpapi

import (
	"encoding/json"
	"net/http"
)

// CombinedJWKSHandler merges RSA (JWK RSA) and Ed25519 (JWK OKP) keys.
func CombinedJWKSHandler(rsa *RSAJWKSIssuer, ed *Ed25519Issuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoCache(w)
		type anyKey map[string]any
		out := struct {
			Keys []anyKey `json:"keys"`
		}{}
		if rsa != nil {
			for kid, pub := range rsa.PubKeys {
				out.Keys = append(out.Keys, anyKey{
					"kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256",
					"n": b64url(pub.N.Bytes()),
					"e": b64url(bigIntToBytes(pub.E)),
				})
			}
		}
		if ed != nil {
			for kid, pub := range ed.PubKeys {
				out.Keys = append(out.Keys, anyKey{
					"kty": "OKP", "use": "sig", "kid": kid, "alg": "EdDSA", "crv": "Ed25519",
					"x": b64url(pub),
				})
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// helper for RSA exponent
func bigIntToBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var b []byte
	for x := e; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	return b
}
