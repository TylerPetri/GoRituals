create extension if not exists citext;

-- Users
create table if not exists users (
  id          bigserial primary key,
  email       citext not null unique,
  first_name  text,
  last_name   text,
  password    text not null,               -- argon2id/bcrypt hash
  user_active boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists idx_users_email on users (email);

-- Refresh tokens (opaque, hashed)
create table if not exists refresh_tokens (
  id           bigserial primary key,
  user_id      bigint not null references users(id) on delete cascade,
  token_hash   text not null,             -- hash(token)
  issued_at    timestamptz not null default now(),
  expires_at   timestamptz not null,
  revoked_at   timestamptz,
  user_agent   text,
  ip           inet
);

create index if not exists idx_refresh_tokens_user on refresh_tokens (user_id);
create index if not exists idx_refresh_tokens_expires on refresh_tokens (expires_at);

-- Simple audit trail
create table if not exists audit_log (
  id         bigserial primary key,
  actor_user bigint,                       -- nullable; system actors too
  action     text not null,
  meta       jsonb not null default '{}',
  created_at timestamptz not null default now()
);
