-- name: GetUserByEmail :one
select id, email, first_name, last_name, password, user_active, created_at, updated_at
from users where email = $1;

-- name: GetUserByID :one
select id, email, first_name, last_name, password, user_active, created_at, updated_at
from users where id = $1;

-- name: ListUsers :many
select id, email, first_name, last_name, password, user_active, created_at, updated_at
from users order by last_name;

-- name: InsertUser :one
insert into users (email, first_name, last_name, password, user_active)
values ($1, $2, $3, $4, $5)
returning id;

-- name: UpdateUser :exec
update users set
  email = $1,
  first_name = $2,
  last_name = $3,
  user_active = $4,
  updated_at = now()
where id = $5;

-- name: DeleteUser :exec
delete from users where id = $1;

-- name: UpdateUserPassword :exec
update users
set password = $1,
    updated_at = now()
where id = $2;