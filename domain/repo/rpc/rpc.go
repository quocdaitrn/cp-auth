package rpc

import "context"

// UserRepo provides all methods to interact with user's domain.
type UserRepo interface {
	// CreateUser creates a new user.
	CreateUser(ctx context.Context, firstName, lastName, email string) (newID uint, err error)
}
