drop table if exists audit_log;
drop table if exists refresh_tokens;
drop table if exists users;
-- (We keep the citext extension; drop it only if you’re sure nothing else uses it.)
