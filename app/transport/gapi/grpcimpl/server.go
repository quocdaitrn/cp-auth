package grpcimpl

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	grpctransport "github.com/go-kit/kit/transport/grpc"

	"github.com/quocdaitrn/cp-auth/app/endpoint"
	"github.com/quocdaitrn/cp-auth/app/transport/gapi/codec"
	"github.com/quocdaitrn/cp-auth/domain/service"
	"github.com/quocdaitrn/cp-auth/proto/pb"
)

type grpcServer struct {
	pb.UnimplementedAuthServiceServer
	introspectToken grpctransport.Handler
}

// NewGRPCServer makes a set of endpoints available as a gRPC AuthServiceServer.
func NewGRPCServer(svc service.AuthService, logger log.Logger) pb.AuthServiceServer {
	opts := []grpctransport.ServerOption{
		grpctransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}
	authSvcEpts := endpoint.NewAuthServiceEndpoints(svc)

	return &grpcServer{
		introspectToken: grpctransport.NewServer(
			authSvcEpts.IntrospectTokenEndpoint,
			codec.DecodeGRPCIntrospectTokenRequest,
			codec.EncodeGRPCIntrospectTokenResponse,
			opts...,
		),
	}
}

func (s *grpcServer) IntrospectToken(ctx context.Context, req *pb.IntrospectRequest) (*pb.IntrospectResponse, error) {
	_, rep, err := s.introspectToken.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.IntrospectResponse), nil
}
