package entity

import "time"

// Auth defines data model for user's auth.
type Auth struct {
	ID         uint      `json:"id" gorm:"primary_key;column:id;auto_increment:true"`
	UserID     uint      `json:"user_id" gorm:"column:user_id"`
	AuthType   string    `json:"auth_type" gorm:"column:auth_type"`
	Email      string    `json:"email" gorm:"column:email"`
	Salt       string    `json:"salt" gorm:"column:salt"`
	Password   string    `json:"password" gorm:"column:password"`
	FacebookID string    `json:"facebook_id" gorm:"column:facebook_id"`
	CreatedAt  time.Time `json:"created_at" gorm:"column:created_at;autocreatetime"`
	UpdatedAt  time.Time `json:"updated_at" gorm:"column:updated_at;autoupdatetime"`
}

func (Auth) TableName() string { return "auths" }

// NewAuthWithEmailPassword creates an Auth from given data.
func NewAuthWithEmailPassword(userID uint, email, salt, password string) Auth {
	return Auth{
		UserID:   userID,
		Email:    email,
		Salt:     salt,
		Password: password,
		AuthType: "email_password",
	}
}
