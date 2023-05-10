package storeimpl

import (
	"context"

	"github.com/quocdaitrn/golang-kit/errors"
	kiterrors "github.com/quocdaitrn/golang-kit/errors"
	"gorm.io/gorm"

	"github.com/quocdaitrn/cp-auth/domain/entity"
	"github.com/quocdaitrn/cp-auth/domain/repo/store"
)

// authRepo implements methods of auth's repository.
type authRepo struct {
	db *gorm.DB
}

// NewAuthRepo creates and returns a new instances of AuthRepo.
func NewAuthRepo(db *gorm.DB) store.AuthRepo {
	return &authRepo{db: db}
}

// InsertOne inserts a user's auth to database.
func (r *authRepo) InsertOne(_ context.Context, auth *entity.Auth) error {
	if err := r.db.Table(auth.TableName()).Create(auth).Error; err != nil {
		return kiterrors.WithStack(err)
	}

	return nil
}

// FindOneByEmail fetches a user's auth from database by email.
func (r *authRepo) FindOneByEmail(_ context.Context, email string) (*entity.Auth, error) {
	var data entity.Auth

	if err := r.db.
		Table(data.TableName()).
		Where("email = ?", email).
		First(&data).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, kiterrors.ErrRepoEntityNotFound
		}

		return nil, errors.WithStack(err)
	}

	return &data, nil
}
