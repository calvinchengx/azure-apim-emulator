// Command azure-apim-emulator runs the local APIM platform emulator.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/config"
	"github.com/calvinchengx/azure-apim-emulator/internal/server"
	"github.com/calvinchengx/azure-apim-emulator/internal/tlscert"
)

var version = "dev"

var (
	fatal           = log.Fatal
	listen          = net.Listen
	serve           = http.Serve
	loadCertificate = tlscert.Load
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fatal(err)
	}
}

func run(args []string) error {
	cfg := config.FromEnvPartial()
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println("azure-apim-emulator", version)
			return nil
		case "healthcheck":
			return healthcheck(cfg.Addr)
		}
	}
	flags := flag.NewFlagSet("azure-apim-emulator", flag.ContinueOnError)
	flags.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address")
	flags.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "state directory (empty = in-memory)")
	flags.StringVar(&cfg.DefaultService, "default-service", cfg.DefaultService, "service used for localhost gateway requests")
	flags.StringVar(&cfg.Location, "location", cfg.Location, "seeded service location")
	flags.BoolVar(&cfg.DisableTLS, "disable-tls", cfg.DisableTLS, "serve plain HTTP")
	flags.BoolVar(&cfg.DisableAuth, "disable-auth", cfg.DisableAuth, "disable ARM bearer-token validation")
	flags.BoolVar(&cfg.StrictPolicies, "strict-policies", cfg.StrictPolicies, "reject unsupported policies during upload")
	flags.StringVar(&cfg.EntraIssuer, "entra-issuer", cfg.EntraIssuer, "trusted Entra v2 issuer")
	flags.StringVar(&cfg.EntraJWKSURL, "entra-jwks-url", cfg.EntraJWKSURL, "JWKS endpoint")
	flags.BoolVar(&cfg.EntraTLSInsecure, "entra-tls-insecure", cfg.EntraTLSInsecure, "skip TLS verification when fetching JWKS")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := cfg.Finish(); err != nil {
		return err
	}
	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
			return err
		}
	}
	srv, err := server.New(cfg, nil, nil, nil)
	if err != nil {
		return err
	}
	defer srv.Close()
	listener, err := listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	scheme := "https"
	if cfg.DisableTLS {
		scheme = "http"
	} else {
		certificate, err := loadCertificate(cfg.DataDir)
		if err != nil {
			return err
		}
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	}
	fmt.Printf("azure-apim-emulator listening on %s://%s (default service: %s)\n", scheme, listener.Addr(), cfg.DefaultService)
	return serve(listener, srv.Handler())
}

func healthcheck(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	endpoint := net.JoinHostPort(host, port)
	response, err := client.Get("https://" + endpoint + "/health")
	if err != nil {
		response, err = client.Get("http://" + endpoint + "/health")
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health: %s", response.Status)
	}
	return nil
}
