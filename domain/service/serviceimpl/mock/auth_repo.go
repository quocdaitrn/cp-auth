// Code generated by mockery v2.20.0. DO NOT EDIT.

package mock

import (
	context "context"

	entity "github.com/quocdaitrn/cp-auth/domain/entity"
	mock "github.com/stretchr/testify/mock"
)

// AuthRepo is an autogenerated mock type for the AuthRepo type
type AuthRepo struct {
	mock.Mock
}

// FindOneByEmail provides a mock function with given fields: ctx, email
func (_m *AuthRepo) FindOneByEmail(ctx context.Context, email string) (*entity.Auth, error) {
	ret := _m.Called(ctx, email)

	var r0 *entity.Auth
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entity.Auth, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entity.Auth); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entity.Auth)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertOne provides a mock function with given fields: ctx, auth
func (_m *AuthRepo) InsertOne(ctx context.Context, auth *entity.Auth) error {
	ret := _m.Called(ctx, auth)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *entity.Auth) error); ok {
		r0 = rf(ctx, auth)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAuthRepo interface {
	mock.TestingT
	Cleanup(func())
}

// NewAuthRepo creates a new instance of AuthRepo. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAuthRepo(t mockConstructorTestingTNewAuthRepo) *AuthRepo {
	mock := &AuthRepo{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}