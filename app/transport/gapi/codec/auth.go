package codec

import (
	"context"

	"github.com/quocdaitrn/cp-auth/domain/service"
	"github.com/quocdaitrn/cp-auth/proto/pb"
)

// DecodeGRPCIntrospectTokenRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC IntrospectToken request to a user-domain GetUser request. Primarily useful in a server.
func DecodeGRPCIntrospectTokenRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.IntrospectRequest)
	return &service.IntrospectTokenRequest{AccessToken: req.AccessToken}, nil
}

// EncodeGRPCIntrospectTokenResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain IntrospectToken response to a gRPC IntrospectToken reply. Primarily useful in a server.
func EncodeGRPCIntrospectTokenResponse(_ context.Context, response interface{}) (interface{}, error) {
	resp := response.(*service.IntrospectTokenResponse)
	return &pb.IntrospectResponse{
		Tid: resp.ID,
		Sub: resp.Subject,
	}, nil
}
