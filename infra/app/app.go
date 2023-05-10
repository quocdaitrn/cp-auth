package app

import (
	"context"
	"github.com/quocdaitrn/cp-auth/infra/adapters"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/quocdaitrn/cp-auth/infra/config"
)

// ApplicationContext application's context.
type ApplicationContext struct {
	ctx context.Context
	cfg config.Config

	restService *adapters.RestService
	grpcService *adapters.GRPCService
}

// Commands returns an App from ApplicationContext.
func (a *ApplicationContext) Commands() *cli.App {
	app := cli.NewApp()
	app.Commands = []*cli.Command{
		a.Serve(),
	}
	return app
}

func HandleSigterm(handleExit func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGTRAP)
	go func() {
		<-c
		logrus.Infof("handle shutdown signal in main thread")
		handleExit()
		os.Exit(1)
	}()
}
