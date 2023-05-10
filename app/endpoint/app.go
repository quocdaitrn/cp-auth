package endpoint

import (
	"context"

	"github.com/go-kit/kit/endpoint"

	"github.com/quocdaitrn/cp-auth/infra/config"
)

// AppServiceEndpoints is a set of app service's endpoints.
type AppServiceEndpoints struct {
	PingAppEndpoint endpoint.Endpoint
}

// NewAppServiceEndpoints creates and returns a new instance of AppServiceEndpoints.
func NewAppServiceEndpoints(
	cfg config.Config,
) *AppServiceEndpoints {
	epts := &AppServiceEndpoints{}

	epts.PingAppEndpoint = newPingAppEndpoint(cfg)

	return epts
}

// PingAppRequest represents a request for PingAppEndpoint.
type PingAppRequest struct {
}

// PingAppResponse represents a response for PingAppEndpoint.
type PingAppResponse struct {
	Message string `json:"message"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// newPingAppEndpoint creates and returns a new endpoint for PingAppEndpoint use
// case.
func newPingAppEndpoint(cfg config.Config) endpoint.Endpoint {
	resp := PingAppResponse{
		"pong",
		cfg.ServiceName,
		cfg.ServiceVersion,
	}

	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return resp, nil
	}
}
