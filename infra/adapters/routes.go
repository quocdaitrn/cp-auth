package adapters

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"

	"github.com/quocdaitrn/cp-auth/app/transport/api/handler"
	"github.com/quocdaitrn/cp-auth/domain/service"
	"github.com/quocdaitrn/cp-auth/infra/config"
)

func ProvideRoutes(taskSvc service.AuthService, logger log.Logger, cfg config.Config) RestAPIHandler {
	r := mux.NewRouter()
	handler.MakeAppHandler(r, logger, cfg)

	v1 := r.PathPrefix("/v1").Subrouter()
	handler.MakeAuthAPIHandler(v1, taskSvc, logger)

	return setupCORSMiddleware(r)
}

func setupCORSMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
		if r.Method == http.MethodOptions {
			// Note: cache CORS for Chrome
			w.WriteHeader(http.StatusOK)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}
