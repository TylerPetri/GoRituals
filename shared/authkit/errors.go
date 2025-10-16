package authkit

import "errors"

var (
	ErrNoAuthHeader = errors.New("missing Authorization: Bearer")
	ErrVerify       = errors.New("token verification failed")
)
