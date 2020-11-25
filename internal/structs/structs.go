package structs

import (
	"database/sql"
)

/* 
Structs are defined here
Most Structs are made for decoding json
*/
type LoginInput struct {
	User string `json:"username"` 
	Pass string	`json:"password"`
}

type RegisterInput struct {
	Username string `json:"username"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type OneString struct {
	Input string `json:"nickname"`
}

type UserTable struct {
	UserID int
	Usern, Email, Pass, Phone, Nickname sql.NullString
}