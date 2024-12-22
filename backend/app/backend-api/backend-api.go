package main

import (
	"net/http"
	"os"
	"test-task3/libs/1_domain_methods/handlers/auth"
	"test-task3/libs/3_infrastructure/db_manager"
	"test-task3/libs/4_common/env_vars"
	"test-task3/libs/4_common/smart_context"

	"github.com/go-chi/chi/v5"
	chi_middleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	env_vars.LoadEnvVars() // load env vars from .env file if ENV_PATH is specified
	os.Setenv("LOG_LEVEL", "debug")

	logger := smart_context.NewSmartContext()

	dbm, err := db_manager.NewDbManager(logger)
	if err != nil {
		logger.Fatalf("Error connecting to database: %v", err)
	}
	logger = logger.WithDbManager(dbm)
	logger = logger.WithDB(dbm.GetGORM())

	r := chi.NewRouter()

	r.Use(chi_middleware.Logger)
	r.Use(chi_middleware.Recoverer)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With", "X-Request-Id", "X-Session-Id", "Apikey", "X-Api-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	auth.AuthRoutes(r, logger)

	logger.Info("Server listening on port 4000")
	err = http.ListenAndServe(":4000", r)
	logger.Fatal(err)
}
