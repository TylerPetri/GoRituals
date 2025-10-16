package httpapi

import (
	"database/sql"

	"github.com/tylerpetri/GoRituals/auth-service/internal/dbgen"
)

func toUserDTO(u dbgen.User) userDTO {
	return userDTO{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: fromNullString(u.FirstName),
		LastName:  fromNullString(u.LastName),
		Active:    u.UserActive,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

func fromNullString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
