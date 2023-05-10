package app

import (
	"github.com/google/wire"
	"github.com/quocdaitrn/cp-auth/app/transport/gapi/grpcimpl"
	"github.com/quocdaitrn/cp-auth/infra/adapters"
	"github.com/quocdaitrn/golang-kit/validator"

	"github.com/quocdaitrn/cp-auth/domain/service/serviceimpl"
	"github.com/quocdaitrn/cp-auth/infra/config"
	"github.com/quocdaitrn/cp-auth/infra/providers"
	"github.com/quocdaitrn/cp-auth/infra/repo/rpcimpl"
	"github.com/quocdaitrn/cp-auth/infra/repo/storeimpl"
)

var ApplicationSet = wire.NewSet(
	config.ProvideConfig,
	validator.New,

	adapters.ProvideMySQL,
	adapters.ProvideRoutes,
	adapters.ProvideRestService,
	providers.ProvideLogger,
	providers.ProvideHasher,
	providers.ProvideJWTProvider,
	providers.ProvideGRPCUserServiceClient,
	grpcimpl.NewGRPCServer,
	adapters.ProvideGRPCService,

	storeimpl.NewAuthRepo,
	rpcimpl.NewUserRepo,
	serviceimpl.NewAuthService,
)
