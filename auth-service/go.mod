module github.com/tylerpetri/GoRituals/auth-service

go 1.24.9

require (
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/jackc/pgconn v1.14.3
	github.com/jackc/pgx/v5 v5.7.6
	github.com/tylerpetri/GoRituals/shared/authkit v0.0.0-20251016224101-0005d8f9f87d
	golang.org/x/crypto v0.43.0
)

require (
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
)

replace github.com/tylerpetri/GoRituals/shared/authkit => ../shared/authkit
