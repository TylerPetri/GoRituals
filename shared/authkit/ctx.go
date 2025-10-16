package authkit

import "context"

type ctxKey string

var (
	ctxClaimsKey ctxKey = "authkit.claims"
)

func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxClaimsKey, c)
}

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxClaimsKey).(*Claims)
	return c, ok
}

func UserIDFromContext(ctx context.Context) (int64, bool) {
	if c, ok := ClaimsFromContext(ctx); ok && c != nil {
		return c.UserID, true
	}
	return 0, false
}
