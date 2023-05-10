package handler

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	golangkithttp "github.com/quocdaitrn/golang-kit/http"

	"github.com/quocdaitrn/cp-auth/app/endpoint"
	"github.com/quocdaitrn/cp-auth/app/transport/api/codec"
	"github.com/quocdaitrn/cp-auth/domain/service"
)

// MakeAuthAPIHandler provides all auth's routes.
func MakeAuthAPIHandler(
	r *mux.Router,
	svc service.AuthService,
	logger log.Logger,
) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		kithttp.ServerErrorEncoder(golangkithttp.DefaultErrorEncoder),
	}
	authSvcEpts := endpoint.NewAuthServiceEndpoints(svc)

	loginHandler := kithttp.NewServer(
		authSvcEpts.LoginEndpoint,
		codec.DecodeLoginRequest,
		golangkithttp.EncodeResponse,
		opts...,
	)

	registerHandler := kithttp.NewServer(
		authSvcEpts.RegisterEndpoint,
		codec.DecodeRegisterRequest,
		golangkithttp.EncodeResponse,
		opts...,
	)

	r.Handle("/auth/login", loginHandler).Methods(http.MethodPost)
	r.Handle("/auth/register", registerHandler).Methods(http.MethodPost)

	return r
}
