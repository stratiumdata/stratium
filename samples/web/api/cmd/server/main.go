package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stratium/samples/micro-research-api/internal/handlers"
	"github.com/stratium/samples/micro-research-api/internal/middleware"
	"github.com/stratium/samples/micro-research-api/internal/platform"
	"github.com/stratium/samples/micro-research-api/internal/repository"
)

func main() {
	// Load configuration from environment
	config := loadConfig()

	// Initialize database
	db, err := initDB(config.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	datasetRepo := repository.NewDatasetRepository(db)

	// Initialize Platform service client
	platformClient, err := platform.NewClient(config.PlatformServiceURL)
	if err != nil {
		log.Fatalf("Failed to initialize Platform service client: %v", err)
	}
	defer platformClient.Close()

	// Initialize middleware
	authMiddleware, err := middleware.NewAuthMiddleware(
		config.OIDCIssuerURL,
		config.OIDCClientID,
		config.OIDCClientSecret,
		userRepo,
	)
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %v", err)
	}

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userRepo)
	datasetHandler := handlers.NewDatasetHandler(datasetRepo, platformClient)

	// Setup Gin router
	router := setupRouter(
		authMiddleware,
		userHandler,
		datasetHandler,
		config,
	)

	// Start server
	srv := &http.Server{
		Addr:    config.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting Micro Research API server on %s", config.Port)
		log.Printf("Platform Service: %s", config.PlatformServiceURL)
		log.Printf("OIDC Issuer: %s", config.OIDCIssuerURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Gracefully shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

// Config holds application configuration
type Config struct {
	Port               string
	DatabaseURL        string
	PlatformServiceURL string
	OIDCIssuerURL      string
	OIDCClientID       string
	OIDCClientSecret   string
	CorsEndpoints      string
}

// loadConfig loads configuration from environment variables
func loadConfig() Config {
	return Config{
		Port:               getEnv("PORT", ":8888"),
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://research:research_password@localhost:5433/micro_research?sslmode=disable"),
		PlatformServiceURL: getEnv("PLATFORM_SERVICE_URL", "localhost:50051"),
		OIDCIssuerURL:      getEnv("OIDC_ISSUER_URL", "http://keycloak:8080/realms/stratium"),
		OIDCClientID:       getEnv("OIDC_CLIENT_ID", "micro-research-api"),
		OIDCClientSecret:   getEnv("OIDC_CLIENT_SECRET", "micro-research-secret"),
		CorsEndpoints:      getEnv("CORS_ENDPOINTS", "http://localhost:3001,http://127.0.0.1:3001"),
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// initDB initializes the database connection
func initDB(databaseURL string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Database connection established")
	return db, nil
}

// setupRouter configures the Gin router with all routes
func setupRouter(
	authMW *middleware.AuthMiddleware,
	userHandler *handlers.UserHandler,
	datasetHandler *handlers.DatasetHandler,
	config Config,
) *gin.Engine {
	router := gin.Default()

	// Configure CORS - must be first middleware to handle preflight
	router.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(config.CorsEndpoints, ","),
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Register explicit OPTIONS handlers for CORS preflight (before auth middleware)
	optionsHandler := func(c *gin.Context) {
		c.Status(204)
	}
	router.OPTIONS("/api/v1/datasets", optionsHandler)
	router.OPTIONS("/api/v1/datasets/*path", optionsHandler)
	router.OPTIONS("/api/v1/users", optionsHandler)
	router.OPTIONS("/api/v1/users/*path", optionsHandler)

	// Health check endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "micro-research-api",
			"version": "1.0.0",
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public routes (no auth)
		public := v1.Group("")
		{
			public.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"message": "Micro Research Repository API",
					"version": "1.0.0",
					"endpoints": gin.H{
						"users":    "/api/v1/users",
						"datasets": "/api/v1/datasets",
						"search":   "/api/v1/datasets/search",
					},
				})
			})
		}

		// Protected routes (require authentication)
		protected := v1.Group("")
		protected.Use(authMW.RequireAuth())
		{
			// User endpoints
			users := protected.Group("/users")
			{
				users.GET("/me", userHandler.GetMe)                             // Get current user
				users.GET("", authMW.RequireAdmin(), userHandler.List)          // List all users (admin only)
				users.GET("/:id", userHandler.Get)                              // Get user by ID
				users.POST("", authMW.RequireAdmin(), userHandler.Create)       // Create user (admin only)
				users.PUT("/:id", userHandler.Update)                           // Update user (self or admin)
				users.DELETE("/:id", authMW.RequireAdmin(), userHandler.Delete) // Delete user (admin only)
			}

			// Dataset endpoints
			datasets := protected.Group("/datasets")
			{
				datasets.GET("", datasetHandler.List)          // List datasets (filtered by department)
				datasets.GET("/search", datasetHandler.Search) // Search datasets (filtered by department)
				datasets.POST("", datasetHandler.Create)       // Create dataset

				// These routes need ABAC checks - handlers must set dataset in context first
				// then call c.Next() to trigger ABAC middleware
				datasets.GET("/:id", datasetHandler.Get)
				datasets.PUT("/:id", datasetHandler.Update)
				datasets.DELETE("/:id", datasetHandler.Delete)
			}
		}
	}

	return router
}
