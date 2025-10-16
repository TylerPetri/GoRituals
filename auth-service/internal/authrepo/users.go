package authrepo

import (
	"context"
	"database/sql"

	"github.com/tylerpetri/GoRituals/auth-service/internal/dbgen"
)

type Users struct {
	q dbgen.Querier // interface emitted by sqlc
}

// NewUsers: pass either *pgxpool.Pool or pgx.Tx (both satisfy dbgen.Querier, thanks to emit_interface)
func NewUsers(q dbgen.Querier) *Users { return &Users{q: q} }

// Params for Argon2id (OWASP-recommended starting point for servers)
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KB
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// Reasonable defaults; tune with load tests.
var DefaultArgon2 = Argon2Params{
	Time: 3, Memory: 64 * 1024, Threads: 2, SaltLen: 16, KeyLen: 32,
}

// Optional app-wide pepper (from KMS/HSM, env injected at boot)
var Pepper []byte

func (u *Users) Create(ctx context.Context, email, first, last, plainPass string, active bool) (int64, error) {
	hash, err := HashPassword(plainPass, DefaultArgon2)
	if err != nil {
		return 0, err
	}
	id, err := u.q.InsertUser(ctx, dbgen.InsertUserParams{
		Email:      email,
		FirstName:  sql.NullString{String: first, Valid: first != ""},
		LastName:   sql.NullString{String: last, Valid: last != ""},
		Password:   hash,
		UserActive: active,
	})
	if err != nil {
		return 0, err
	}
	return int64(id), nil
}

func (u *Users) GetByEmail(ctx context.Context, email string) (dbgen.User, error) {
	return u.q.GetUserByEmail(ctx, email)
}

func (u *Users) UpdateProfile(ctx context.Context, id int64, email, first, last string, active bool) error {
	return u.q.UpdateUser(ctx, dbgen.UpdateUserParams{
		Email:      email,
		FirstName:  sql.NullString{String: first, Valid: first != ""},
		LastName:   sql.NullString{String: last, Valid: last != ""},
		UserActive: active,
		ID:         int64(id),
	})
}

func (u *Users) DeleteByID(ctx context.Context, id int64) error {
	return u.q.DeleteUser(ctx, int64(id))
}

func (u *Users) ResetPassword(ctx context.Context, id int64, newPlain string) error {
	hash, err := HashPassword(newPlain, DefaultArgon2)
	if err != nil {
		return err
	}
	return u.q.UpdateUserPassword(ctx, dbgen.UpdateUserPasswordParams{
		Password: hash,
		ID:       id,
	})
}
