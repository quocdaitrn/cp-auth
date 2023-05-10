package main

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/quocdaitrn/cp-auth/infra/app"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	cli, cleanup, err := app.InitApplication(ctx)
	if err != nil {
		logrus.WithError(err).Fatal("cannot init application")
	}

	app.HandleSigterm(func() {
		cancel()
		cleanup()
	})

	err = cli.Commands().Run(os.Args)
	if err != nil {
		logrus.WithError(err).Fatal("cannot start application")
	}
}
