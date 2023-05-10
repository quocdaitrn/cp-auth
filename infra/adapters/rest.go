package adapters

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/quocdaitrn/cp-auth/infra/config"
)

type RestAPIHandler http.Handler

type RestService struct {
	started bool
	srv     http.Server
}

func (s *RestService) MustStart() {
	s.started = true
	if err := s.srv.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			panic(fmt.Sprintf("Can not start HTTP server, error: %s", err.Error()))
		} else {
			fmt.Println("The HTTP server is shutting down...")
		}
	}
}

func (s *RestService) Close() {
	if s.started {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.srv.Shutdown(ctx); err != nil {
			panic(fmt.Sprintf("The HTTP server didn't shut down before timeout, error: %s", err.Error()))
		} else {
			fmt.Println("The HTTP server was shut down")
		}
	}
}

func ProvideRestService(cfg config.Config, handler RestAPIHandler) (*RestService, func(), error) {
	port := strconv.Itoa(cfg.HTTPServerPort)
	if port == "" {
		port = "8080"
	}

	rest := &RestService{
		started: false,
		srv: http.Server{
			Addr:    ":" + port,
			Handler: handler,

			// Good practice: enforce timeouts for servers you create!
			ReadTimeout:  2 * time.Minute,
			WriteTimeout: 2 * time.Minute,
		},
	}
	logrus.Infof("Init rest APIs client at address %s", rest.srv.Addr)
	return rest, func() {
		logrus.Info("Cleanup rest service")
		rest.Close()
	}, nil
}
