package handler

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	"github.com/quocdaitrn/cp-auth/app/endpoint"
	"github.com/quocdaitrn/cp-auth/infra/config"
)

func MakeAppHandler(
	r *mux.Router,
	logger log.Logger,
	cfg config.Config,
) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}
	appEpts := endpoint.NewAppServiceEndpoints(cfg)

	r.Methods(http.MethodGet).Path("/ping").Handler(kithttp.NewServer(
		appEpts.PingAppEndpoint,
		kithttp.NopRequestDecoder,
		kithttp.EncodeJSONResponse,
		opts...,
	))

	return r
}
