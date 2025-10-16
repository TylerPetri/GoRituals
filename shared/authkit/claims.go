package authkit

import "time"

type Claims struct {
	UserID int64    `json:"uid"`
	Scopes []string `json:"scp,omitempty"`

	Iss string    `json:"iss"`
	Aud string    `json:"aud"`
	Exp time.Time `json:"exp"`
	Sub string    `json:"sub,omitempty"`
	Jti string    `json:"jti,omitempty"`
}
