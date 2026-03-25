package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	defaultAddr = ":8099"
)

//go:embed public/*
var staticFS embed.FS

func main() {
	mux := http.NewServeMux()

	mux.Handle("/", staticHandler())

	addr := envOrDefault("YUBIKEY_WEB_SAMPLE_ADDR", defaultAddr)
	log.Printf("YubiKey browser sample listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "public")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
