-- Backfill any existing NULLs to safe defaults
update refresh_tokens
set user_agent = coalesce(user_agent, '');

-- If ip is inet, give it a valid placeholder address
update refresh_tokens
set ip = coalesce(ip, '0.0.0.0'::inet);

-- Enforce NOT NULL + defaults
alter table refresh_tokens
  alter column user_agent set default '',
  alter column user_agent set not null;

alter table refresh_tokens
  alter column ip set not null;
