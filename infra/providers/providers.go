package providers

import (
	"os"

	"github.com/go-kit/kit/log"
	kitauth "github.com/quocdaitrn/golang-kit/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/quocdaitrn/cp-auth/domain/service"
	"github.com/quocdaitrn/cp-auth/infra/config"
	"github.com/quocdaitrn/cp-auth/proto/pb"
)

func ProvideLogger() log.Logger {
	var logger log.Logger
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	return logger
}

func ProvideJWTProvider(cfg config.Config) kitauth.JWTProvider {
	jwt := kitauth.NewJWT(cfg.JwtID)
	jwt.InitFlags()
	return jwt
}

func ProvideHasher() service.Hasher {
	return &kitauth.Hasher{}
}

func ProvideGRPCUserServiceClient(cfg config.Config) (pb.UserServiceClient, error) {
	opts := grpc.WithTransportCredentials(insecure.NewCredentials())
	clientConn, err := grpc.Dial(cfg.GRPCServerUserServiceAddress, opts)
	if err != nil {
		return nil, err
	}

	return pb.NewUserServiceClient(clientConn), nil
}
