-- Revert constraints; we don't attempt to "un-backfill" values
alter table refresh_tokens
  alter column ua drop not null,
  alter column ua drop default;

alter table refresh_tokens
  alter column ip drop not null;
