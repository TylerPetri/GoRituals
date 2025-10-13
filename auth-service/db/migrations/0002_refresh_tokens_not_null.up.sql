-- Backfill any existing NULLs to safe defaults
update refresh_tokens
set ua = coalesce(ua, '');

-- If ip is inet, give it a valid placeholder address
update refresh_tokens
set ip = coalesce(ip, '0.0.0.0'::inet);

-- Enforce NOT NULL + defaults
alter table refresh_tokens
  alter column ua set default '',
  alter column ua set not null;

alter table refresh_tokens
  alter column ip set not null;
