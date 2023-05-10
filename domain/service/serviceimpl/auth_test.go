package serviceimpl

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	kiterrors "github.com/quocdaitrn/golang-kit/errors"
	"github.com/quocdaitrn/golang-kit/validator"
	"github.com/stretchr/testify/mock"
	"reflect"
	"strings"
	"testing"

	"github.com/quocdaitrn/cp-auth/domain"
	"github.com/quocdaitrn/cp-auth/domain/entity"
	"github.com/quocdaitrn/cp-auth/domain/service"
	servicemock "github.com/quocdaitrn/cp-auth/domain/service/serviceimpl/mock"
)

func Test_authService_IntrospectToken(t *testing.T) {
	type jwtProviderParseTokenArgs struct {
		accessToken string
	}
	type jwtProviderParseTokenWant struct {
		claim *jwt.RegisteredClaims
		err   error
	}

	type args struct {
		ctx context.Context
		req *service.IntrospectTokenRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *service.IntrospectTokenResponse
		wantErr bool
		err     error

		// mocks
		jwtProviderParseTokenArgs
		jwtProviderParseTokenWant
	}{
		{
			name: "parse token successfully",
			args: args{
				ctx: context.Background(),
				req: &service.IntrospectTokenRequest{AccessToken: "access_token"},
			},
			want: &service.IntrospectTokenResponse{RegisteredClaims: &jwt.RegisteredClaims{
				Issuer:  "Anonymous",
				Subject: "abc@gmail.com",
			}},
			wantErr: false,

			jwtProviderParseTokenArgs: jwtProviderParseTokenArgs{accessToken: "access_token"},
			jwtProviderParseTokenWant: jwtProviderParseTokenWant{
				claim: &jwt.RegisteredClaims{
					Issuer:  "Anonymous",
					Subject: "abc@gmail.com",
				},
			},
		},
		{
			name: "parse token fail",
			args: args{
				ctx: context.Background(),
				req: &service.IntrospectTokenRequest{AccessToken: "access_token"},
			},
			wantErr: true,
			err:     kiterrors.ErrUnauthorized,

			jwtProviderParseTokenArgs: jwtProviderParseTokenArgs{accessToken: "access_token"},
			jwtProviderParseTokenWant: jwtProviderParseTokenWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "invalid request",
			args: args{
				ctx: context.Background(),
				req: &service.IntrospectTokenRequest{},
			},
			wantErr: true,
			err:     errors.New("AccessToken is a required field"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtProvider := &servicemock.JWTProvider{}
			v, _ := validator.New()

			jwtProvider.On("ParseToken", tt.args.ctx, tt.jwtProviderParseTokenArgs.accessToken).Return(
				tt.jwtProviderParseTokenWant.claim,
				tt.jwtProviderParseTokenWant.err,
			)

			s := &authService{
				jwtProvider: jwtProvider,
				validator:   v,
			}
			got, err := s.IntrospectToken(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("IntrospectToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.err.Error()) {
					t.Errorf("Login() got err = %v, want err = %v", err.Error(), tt.err.Error())
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IntrospectToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authService_Login(t *testing.T) {
	type authRepoFindOneByEmailArgs struct {
		email string
	}
	type authRepoFindOneByEmailWant struct {
		ent *entity.Auth
		err error
	}

	type hasherCompareHashPasswordArgs struct {
		hashedPass string
		salt       string
		checkPass  string
	}
	type hasherCompareHashPasswordWant struct {
		match bool
	}

	type jwtProviderIssueTokenArgs struct {
		sub string
	}
	type jwtProviderIssueTokenWant struct {
		token   string
		expSecs int
		err     error
	}

	type args struct {
		ctx context.Context
		req *service.LoginRequest
	}

	tests := []struct {
		name    string
		args    args
		want    *service.LoginResponse
		wantErr bool
		err     error

		// mocks
		authRepoFindOneByEmailArgs
		authRepoFindOneByEmailWant

		hasherCompareHashPasswordArgs
		hasherCompareHashPasswordWant

		jwtProviderIssueTokenArgs
		jwtProviderIssueTokenWant
	}{
		{
			name: "login successfully with valid info",
			args: args{
				ctx: context.Background(),
				req: &service.LoginRequest{
					Email:    "abc@gmail.com",
					Password: "12345678",
				},
			},
			want: &service.LoginResponse{
				AccessToken: domain.Token{
					Token:     "abc",
					ExpiredIn: 900,
				},
			},
			wantErr: false,

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				ent: &entity.Auth{
					ID:       1,
					UserID:   1,
					AuthType: "email_password",
					Email:    "abc@gmail.com",
					Salt:     "123",
					Password: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				},
			},

			hasherCompareHashPasswordArgs: hasherCompareHashPasswordArgs{
				hashedPass: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				salt:       "123",
				checkPass:  "12345678",
			},
			hasherCompareHashPasswordWant: hasherCompareHashPasswordWant{match: true},

			jwtProviderIssueTokenArgs: jwtProviderIssueTokenArgs{
				sub: "e532qos8jjM2",
			},
			jwtProviderIssueTokenWant: jwtProviderIssueTokenWant{
				token:   "abc",
				expSecs: 900,
			},
		},
		{
			name: "login fail with wrong email",
			args: args{
				ctx: context.Background(),
				req: &service.LoginRequest{
					Email:    "abc@gmail.com",
					Password: "12345678",
				},
			},
			want:    nil,
			wantErr: true,
			err:     kiterrors.ErrRepoEntityNotFound,

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				err: kiterrors.ErrRepoEntityNotFound,
			},
		},
		{
			name: "login fail with wrong password",
			args: args{
				ctx: context.Background(),
				req: &service.LoginRequest{
					Email:    "abc@gmail.com",
					Password: "12345678",
				},
			},
			want:    nil,
			wantErr: true,
			err:     domain.ErrIncorrectPassword,

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				ent: &entity.Auth{
					ID:       1,
					UserID:   1,
					AuthType: "email_password",
					Email:    "abc@gmail.com",
					Salt:     "123",
					Password: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				},
			},

			hasherCompareHashPasswordArgs: hasherCompareHashPasswordArgs{
				hashedPass: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				salt:       "123",
				checkPass:  "12345678",
			},
			hasherCompareHashPasswordWant: hasherCompareHashPasswordWant{match: false},
		},
		{
			name: "login fail because error occurs when the system issues jwt token",
			args: args{
				ctx: context.Background(),
				req: &service.LoginRequest{
					Email:    "abc@gmail.com",
					Password: "12345678",
				},
			},
			want:    nil,
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				ent: &entity.Auth{
					ID:       1,
					UserID:   1,
					AuthType: "email_password",
					Email:    "abc@gmail.com",
					Salt:     "123",
					Password: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				},
			},

			hasherCompareHashPasswordArgs: hasherCompareHashPasswordArgs{
				hashedPass: "99e0ea1a40c9b1d54308c421da1ee9797877cc44",
				salt:       "123",
				checkPass:  "12345678",
			},
			hasherCompareHashPasswordWant: hasherCompareHashPasswordWant{match: true},

			jwtProviderIssueTokenArgs: jwtProviderIssueTokenArgs{
				sub: "e532qos8jjM2",
			},
			jwtProviderIssueTokenWant: jwtProviderIssueTokenWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "login fail with invalid email",
			args: args{
				ctx: context.Background(),
				req: &service.LoginRequest{
					Email:    "abc@gmail",
					Password: "12345678",
				},
			},
			want:    nil,
			wantErr: true,
			err:     errors.New("Message: invalid request. Details: map[string]string{\"Email\":\"Email must be a valid email address\"}."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRepo := &servicemock.AuthRepo{}
			hasher := &servicemock.Hasher{}
			jwtProvider := &servicemock.JWTProvider{}
			v, _ := validator.New()

			authRepo.On("FindOneByEmail", tt.args.ctx, tt.authRepoFindOneByEmailArgs.email).Return(
				tt.authRepoFindOneByEmailWant.ent,
				tt.authRepoFindOneByEmailWant.err,
			).Once()

			hasher.On("CompareHashPassword", tt.hasherCompareHashPasswordArgs.hashedPass,
				tt.hasherCompareHashPasswordArgs.salt, tt.hasherCompareHashPasswordArgs.checkPass).Return(
				tt.hasherCompareHashPasswordWant.match,
			).Once()

			jwtProvider.On("IssueToken", tt.args.ctx, mock.AnythingOfType("string"), tt.jwtProviderIssueTokenArgs.sub).Return(
				tt.jwtProviderIssueTokenWant.token,
				tt.jwtProviderIssueTokenWant.expSecs,
				tt.jwtProviderIssueTokenWant.err,
			).Once()

			s := &authService{
				authRepo:    authRepo,
				jwtProvider: jwtProvider,
				hasher:      hasher,
				validator:   v,
			}

			got, err := s.Login(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.err.Error()) {
					t.Errorf("Login() got err = %v, want err = %v", err.Error(), tt.err.Error())
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Login() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authService_Register(t *testing.T) {
	type authRepoFindOneByEmailArgs struct {
		email string
	}
	type authRepoFindOneByEmailWant struct {
		ent *entity.Auth
		err error
	}

	type userRepoCreateUserArgs struct {
		firstName string
		lastName  string
		email     string
	}
	type userRepoCreateUserWant struct {
		newID uint
		err   error
	}

	type hasherRandomStrWant struct {
		salt string
		err  error
	}

	type hasherHashPasswordArgs struct {
		password string
	}
	type hasherHashPasswordWant struct {
		hashedPass string
		err        error
	}

	type authRepoInsertOneArgs struct {
		authEntity *entity.Auth
	}
	type authRepoInsertOneWant struct {
		err error
	}

	type args struct {
		ctx context.Context
		req *service.RegisterRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *service.RegisterResponse
		wantErr bool
		err     error

		// mocks
		authRepoFindOneByEmailArgs
		authRepoFindOneByEmailWant

		userRepoCreateUserArgs
		userRepoCreateUserWant

		hasherRandomStrWant

		hasherHashPasswordArgs
		hasherHashPasswordWant

		authRepoInsertOneArgs
		authRepoInsertOneWant
	}{
		{
			name: "register new user successfully",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			want:    &service.RegisterResponse{Message: "register user successlly"},
			wantErr: false,

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				newID: 1,
			},

			hasherRandomStrWant: hasherRandomStrWant{salt: "123"},

			hasherHashPasswordArgs: hasherHashPasswordArgs{password: "12345678"},
			hasherHashPasswordWant: hasherHashPasswordWant{
				hashedPass: "hashed_pass",
			},

			authRepoInsertOneArgs: authRepoInsertOneArgs{authEntity: &entity.Auth{
				UserID:   1,
				AuthType: "email_password",
				Email:    "abc@gmail.com",
				Password: "hashed_pass",
			}},
			authRepoInsertOneWant: authRepoInsertOneWant{},
		},
		{
			name: "register new user fail because getting auth of register email got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail because creating a new user entity got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail because email has already registered",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     domain.ErrRegisterEmailAlreadyExist,

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{
				ent: &entity.Auth{
					ID:       1,
					UserID:   1,
					AuthType: "email_password",
					Email:    "abc@gmail.com",
					Salt:     "123",
					Password: "sjkh292rfhawlr2",
				},
			},
		},
		{
			name: "register new user fail because creating a new user entity got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail because generating salt got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				newID: 1,
			},

			hasherRandomStrWant: hasherRandomStrWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail because hashing password got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				newID: 1,
			},

			hasherRandomStrWant: hasherRandomStrWant{
				salt: "123",
			},

			hasherHashPasswordArgs: hasherHashPasswordArgs{password: "12345678"},
			hasherHashPasswordWant: hasherHashPasswordWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail because creating new user auth got an error",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail.com",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("something went wrong"),

			authRepoFindOneByEmailArgs: authRepoFindOneByEmailArgs{email: "abc@gmail.com"},
			authRepoFindOneByEmailWant: authRepoFindOneByEmailWant{},

			userRepoCreateUserArgs: userRepoCreateUserArgs{
				firstName: "David",
				lastName:  "Beckham",
				email:     "abc@gmail.com",
			},
			userRepoCreateUserWant: userRepoCreateUserWant{
				newID: 1,
			},

			hasherRandomStrWant: hasherRandomStrWant{
				salt: "123",
			},

			hasherHashPasswordArgs: hasherHashPasswordArgs{password: "12345678"},
			hasherHashPasswordWant: hasherHashPasswordWant{
				hashedPass: "hashed_pass",
			},

			authRepoInsertOneArgs: authRepoInsertOneArgs{authEntity: &entity.Auth{
				UserID:   1,
				AuthType: "email_password",
				Email:    "abc@gmail.com",
				Password: "hashed_pass",
			}},
			authRepoInsertOneWant: authRepoInsertOneWant{
				err: errors.New("something went wrong"),
			},
		},
		{
			name: "register new user fail with invalid email",
			args: args{
				ctx: context.Background(),
				req: &service.RegisterRequest{
					FirstName: "David",
					LastName:  "Beckham",
					Email:     "abc@gmail",
					Password:  "12345678",
				},
			},
			wantErr: true,
			err:     errors.New("Email must be a valid email address"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRepo := &servicemock.AuthRepo{}
			userRepo := &servicemock.UserRepo{}
			hasher := &servicemock.Hasher{}
			v, _ := validator.New()

			authRepo.On("FindOneByEmail", tt.args.ctx, tt.authRepoFindOneByEmailArgs.email).Return(
				tt.authRepoFindOneByEmailWant.ent,
				tt.authRepoFindOneByEmailWant.err,
			).Once()

			hasher.On("RandomStr", mock.Anything).Return(
				tt.hasherRandomStrWant.salt,
				tt.hasherRandomStrWant.err,
			).Once()

			hasher.On("HashPassword", tt.hasherRandomStrWant.salt, tt.hasherHashPasswordArgs.password).Return(
				tt.hasherHashPasswordWant.hashedPass,
				tt.hasherHashPasswordWant.err,
			).Once()

			userRepo.On("CreateUser", tt.args.ctx, tt.userRepoCreateUserArgs.firstName,
				tt.userRepoCreateUserArgs.lastName, tt.userRepoCreateUserArgs.email).Return(
				tt.userRepoCreateUserWant.newID,
				tt.userRepoCreateUserWant.err,
			).Once()

			authRepo.On("InsertOne", tt.args.ctx, mock.MatchedBy(func(ae *entity.Auth) bool {
				return ae.Email == tt.authRepoInsertOneArgs.authEntity.Email &&
					ae.UserID == tt.authRepoInsertOneArgs.authEntity.UserID &&
					ae.Password == tt.authRepoInsertOneArgs.authEntity.Password &&
					ae.AuthType == tt.authRepoInsertOneArgs.authEntity.AuthType
			})).Return(
				tt.authRepoInsertOneWant.err,
			).Once()

			s := &authService{
				authRepo:  authRepo,
				userRepo:  userRepo,
				hasher:    hasher,
				validator: v,
			}
			got, err := s.Register(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.err.Error()) {
					t.Errorf("Register() got err = %v, want err = %v", err, tt.err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Register() got = %v, want %v", got, tt.want)
			}
		})
	}
}
