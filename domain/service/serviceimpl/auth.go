package serviceimpl

import (
	"context"

	"github.com/google/uuid"
	kitauth "github.com/quocdaitrn/golang-kit/auth"
	kiterrors "github.com/quocdaitrn/golang-kit/errors"
	"github.com/quocdaitrn/golang-kit/validator"
	"github.com/viettranx/service-context/core"

	"github.com/quocdaitrn/cp-auth/domain"
	"github.com/quocdaitrn/cp-auth/domain/entity"
	"github.com/quocdaitrn/cp-auth/domain/repo/rpc"
	"github.com/quocdaitrn/cp-auth/domain/repo/store"
	"github.com/quocdaitrn/cp-auth/domain/service"
)

type authService struct {
	authRepo    store.AuthRepo
	userRepo    rpc.UserRepo
	jwtProvider kitauth.JWTProvider
	hasher      service.Hasher
	validator   validator.Validator
}

// NewAuthService creates and returns a new instance of AuthService.
func NewAuthService(
	authRepo store.AuthRepo,
	userRepo rpc.UserRepo,
	jwtProvider kitauth.JWTProvider,
	hasher service.Hasher,
	validator validator.Validator,
) service.AuthService {
	return &authService{
		authRepo:    authRepo,
		userRepo:    userRepo,
		jwtProvider: jwtProvider,
		hasher:      hasher,
		validator:   validator,
	}
}

// Login logins a user.
func (s *authService) Login(ctx context.Context, req *service.LoginRequest) (*service.LoginResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, kiterrors.WithStack(err)
	}

	authData, err := s.authRepo.FindOneByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	if !s.hasher.CompareHashPassword(authData.Password, authData.Salt, req.Password) {
		return nil, domain.ErrIncorrectPassword
	}

	uid := core.NewUID(uint32(authData.UserID), 1, 1)
	sub := uid.String()
	tid := uuid.New().String()

	tokenStr, expSecs, err := s.jwtProvider.IssueToken(ctx, tid, sub)
	if err != nil {
		return nil, err
	}

	return &service.LoginResponse{
		AccessToken: domain.Token{
			Token:     tokenStr,
			ExpiredIn: expSecs,
		},
	}, nil
}

// Register registers a new user.
func (s *authService) Register(ctx context.Context, req *service.RegisterRequest) (*service.RegisterResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, kiterrors.WithStack(err)
	}

	a, err := s.authRepo.FindOneByEmail(ctx, req.Email)
	if err != nil {
		if err != kiterrors.ErrRepoEntityNotFound {
			return nil, err
		}
	}
	if a != nil {
		return nil, domain.ErrRegisterEmailAlreadyExist
	}

	newUserID, err := s.userRepo.CreateUser(ctx, req.FirstName, req.LastName, req.Email)
	if err != nil {
		return nil, err
	}

	salt, err := s.hasher.RandomStr(16)
	if err != nil {
		return nil, err
	}

	passHashed, err := s.hasher.HashPassword(salt, req.Password)
	if err != nil {
		return nil, err
	}

	newAuth := entity.NewAuthWithEmailPassword(newUserID, req.Email, salt, passHashed)
	if err := s.authRepo.InsertOne(ctx, &newAuth); err != nil {
		return nil, err
	}

	return &service.RegisterResponse{Message: "register user successfully"}, nil
}

// IntrospectToken validates and extracts info from user's access token.
func (s *authService) IntrospectToken(ctx context.Context, req *service.IntrospectTokenRequest) (*service.IntrospectTokenResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, kiterrors.WithStack(err)
	}

	claims, err := s.jwtProvider.ParseToken(ctx, req.AccessToken)
	if err != nil {
		return nil, kiterrors.ErrUnauthorized.WithDetails(err)
	}

	return &service.IntrospectTokenResponse{RegisteredClaims: claims}, nil
}
