package app

import "github.com/urfave/cli/v2"

// Serve starts Restfull service.
func (a *ApplicationContext) Serve() *cli.Command {
	return &cli.Command{
		Name:        "serve",
		UsageText:   "Start REST API",
		Description: "Command to start REST API service",
		Action: func(ctx *cli.Context) error {
			go a.grpcService.MustStart()
			a.restService.MustStart()
			return nil
		},
	}
}
