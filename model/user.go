package model

import "time"

type User struct {
	ID          uint   `gorm:"primaryKey"`
	Username    string `gorm:"unique"`
	Password    string
	Email       string
	Phone       string
	Token       string
	TokenExpiry time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
