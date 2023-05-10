package codec

import (
	"context"
	"net/http"

	kithttp "github.com/quocdaitrn/golang-kit/http"

	"github.com/quocdaitrn/cp-auth/domain/service"
)

// DecodeLoginRequest decodes LoginRequest from http.Request.
func DecodeLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := &service.LoginRequest{}
	if err := kithttp.Bind(r, req); err != nil {
		return nil, err
	}
	return req, nil
}

// DecodeRegisterRequest decodes RegisterRequest from http.Request.
func DecodeRegisterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := &service.RegisterRequest{}
	if err := kithttp.Bind(r, req); err != nil {
		return nil, err
	}
	return req, nil
}
