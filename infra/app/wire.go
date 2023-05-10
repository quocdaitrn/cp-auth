//go:build wireinject
// +build wireinject

package app

import (
	"context"

	"github.com/google/wire"
)

// InitApplication inits application.
func InitApplication(ctx context.Context) (*ApplicationContext, func(), error) {
	wire.Build(
		ApplicationSet,
		wire.Struct(new(ApplicationContext), "*"),
	)
	return &ApplicationContext{}, nil, nil
}
