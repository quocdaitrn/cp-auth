package service

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/quocdaitrn/cp-auth/domain"
)

// AuthService exposes all available use cases of user's auth domain.
type AuthService interface {
	// Login logins a user.
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)

	// Register registers a new user.
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)

	// IntrospectToken validates and extracts info from user's access token.
	IntrospectToken(ctx context.Context, req *IntrospectTokenRequest) (*IntrospectTokenResponse, error)
}

// Hasher exposes all available methods for supporting to provide hash password.
type Hasher interface {
	// RandomStr generates a random string with given length.
	RandomStr(length int) (string, error)

	// HashPassword hashes a password with given salt.
	HashPassword(salt, password string) (string, error)

	// CompareHashPassword compares a given password is corresponding with a hashed password or not.
	CompareHashPassword(hashedPassword, salt, password string) bool
}

// LoginRequest represents a request to login a user.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=30"`
}

// LoginResponse represents a response to a login user request.
type LoginResponse struct {
	AccessToken domain.Token `json:"access_token"`
	// RefreshToken will be used when access token expired
	// to issue new pair access token and refresh token.
	RefreshToken *domain.Token `json:"refresh_token,omitempty"`
}

// RegisterRequest represents a request to register a new user.
type RegisterRequest struct {
	FirstName string `json:"first_name" validate:"required,max=60"`
	LastName  string `json:"last_name" validate:"required,max=60"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8,max=30"`
}

// RegisterResponse represents a response for registering a new user request.
type RegisterResponse struct {
	Message string `json:"message"`
}

// IntrospectTokenRequest represents a request to introspect access token.
type IntrospectTokenRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

type IntrospectTokenResponse struct {
	*jwt.RegisteredClaims
}
