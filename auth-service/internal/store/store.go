package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tylerpetri/GoRituals/auth-service/internal/dbgen"
)

type Store struct {
	Pool *pgxpool.Pool
}

// Callback gets a dbgen.Querier (the interface sqlc generated).
func (s *Store) WithTx(ctx context.Context, fn func(ctx context.Context, q dbgen.Querier) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{}) // pgx.Tx
	if err != nil {
		return err
	}
	q := dbgen.New(tx) // tx satisfies sqlc’s connection interface
	if err := fn(ctx, q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// For non-transactional paths you can pass the pool:
func (s *Store) WithDB(ctx context.Context, fn func(ctx context.Context, q dbgen.Querier) error) error {
	q := dbgen.New(s.Pool) // pool also satisfies sqlc’s interface
	return fn(ctx, q)
}

type Config struct {
	DSN             string // e.g. postgres://user:pass@host:5432/db?sslmode=verify-full&statement_timeout=3000
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthTimeout   time.Duration
}

func Open(ctx context.Context, cfg Config) (*Store, error) {
	conf, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if cfg.MaxConns > 0 {
		conf.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		conf.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		conf.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		conf.MaxConnIdleTime = cfg.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	s := &Store{Pool: pool}

	// health check
	ctx, cancel := context.WithTimeout(ctx, cfg.HealthTimeout)
	defer cancel()
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.Pool.Close() }

func (s *Store) Ping(ctx context.Context) error {
	return s.Pool.Ping(ctx)
}
