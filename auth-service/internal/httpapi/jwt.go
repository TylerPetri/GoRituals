package httpapi

import (
	"context"
	"time"
)

type JWTIssuer interface {
	IssueAccessToken(ctx context.Context, userID int64, ttl time.Duration) (string, error)
}
