package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"

	"github.com/quocdaitrn/cp-auth/domain/service"
)

// AuthServiceEndpoints is a set of domain service.AuthService's endpoints.
type AuthServiceEndpoints struct {
	LoginEndpoint           endpoint.Endpoint
	RegisterEndpoint        endpoint.Endpoint
	IntrospectTokenEndpoint endpoint.Endpoint
}

// NewAuthServiceEndpoints creates and returns a new instance of
// AuthServiceEndpoints.
func NewAuthServiceEndpoints(
	svc service.AuthService,
) *AuthServiceEndpoints {
	epts := &AuthServiceEndpoints{}

	epts.LoginEndpoint = newLoginEndpoint(svc)
	epts.RegisterEndpoint = newRegisterEndpoint(svc)
	epts.IntrospectTokenEndpoint = newIntrospectTokenEndpoint(svc)

	return epts
}

// newLoginEndpoint creates and returns a new endpoint for
// Login use case.
func newLoginEndpoint(svc service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return svc.Login(ctx, request.(*service.LoginRequest))
	}
}

// newRegisterEndpoint creates and returns a new endpoint for
// Register use case.
func newRegisterEndpoint(svc service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return svc.Register(ctx, request.(*service.RegisterRequest))
	}
}

// newIntrospectTokenEndpoint creates and returns a new endpoint for
// IntrospectToken use case.
func newIntrospectTokenEndpoint(svc service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return svc.IntrospectToken(ctx, request.(*service.IntrospectTokenRequest))
	}
}
