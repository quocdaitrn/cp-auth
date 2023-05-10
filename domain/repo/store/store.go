package store

import (
	"context"

	"github.com/quocdaitrn/cp-auth/domain/entity"
)

// AuthRepo provides methods for interacting with user's auth data.
type AuthRepo interface {
	// InsertOne inserts a user's auth to database.
	InsertOne(ctx context.Context, auth *entity.Auth) error

	// FindOneByEmail fetches a user's auth from database by email.
	FindOneByEmail(ctx context.Context, email string) (*entity.Auth, error)
}
