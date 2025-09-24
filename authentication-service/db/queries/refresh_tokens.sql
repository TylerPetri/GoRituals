-- name: InsertRefreshToken :one
insert into refresh_tokens (user_id, token_hash, expires_at, user_agent, ip)
values ($1, $2, $3, $4, $5)
returning id;

-- name: GetRefreshTokenByHash :one
select id, user_id, token_hash, issued_at, expires_at, revoked_at, user_agent, ip
from refresh_tokens where token_hash = $1;

-- name: RevokeRefreshToken :exec
update refresh_tokens set revoked_at = now() where id = $1;

-- name: RevokeAllForUser :exec
update refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null;

-- name: DeleteExpiredTokens :exec
delete from refresh_tokens where expires_at < now();
