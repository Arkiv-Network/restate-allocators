package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/Arkiv-Network/restate-allocators/pkg/ipallocator"
	"github.com/Arkiv-Network/restate-allocators/pkg/networkidallocator"
	"github.com/Arkiv-Network/restate-allocators/pkg/portallocator"
	restate "github.com/restatedev/sdk-go"
	"github.com/restatedev/sdk-go/server"
	"github.com/urfave/cli/v2"
)

var (
	Version   = "dev"
	CommitSHA = "none"
	Date      = "unknown"
)

const (
	EnvironmentProduction = "production"
	EnvironmentStaging    = "staging"
)

func main() {
	cfg := struct {
		environment string
		addr        string
		logLevel    string
	}{}

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("restate-allocators version %s\n", Version)
		fmt.Printf("  commit: %s\n", CommitSHA)
		fmt.Printf("  built:  %s\n", Date)
	}

	app := &cli.App{
		Name:    "restate-allocators",
		Version: Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "environment",
				Usage:       fmt.Sprintf("Environment (%s or %s)", EnvironmentStaging, EnvironmentProduction),
				EnvVars:     []string{"ENVIRONMENT"},
				Destination: &cfg.environment,
				Required:    true,
				Action: func(ctx *cli.Context, v string) error {
					switch v {
					case EnvironmentStaging, EnvironmentProduction:
						return nil
					default:
						return fmt.Errorf("Invalid environment. Valid values: [%s, %s]", EnvironmentStaging, EnvironmentProduction)
					}
				},
			},
			&cli.StringFlag{
				Name:        "addr",
				Value:       ":9080",
				Usage:       "address to listen on",
				Destination: &cfg.addr,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Value:       "info",
				Usage:       "log level (debug, info, warn, error)",
				EnvVars:     []string{"LOG_LEVEL"},
				Destination: &cfg.logLevel,
			},
		},
		Action: func(c *cli.Context) error {
			// Configure log level
			var level slog.Level
			switch cfg.logLevel {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				level = slog.LevelInfo
			}

			logger := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: level,
			})

			server := server.NewRestate().
				WithLogger(logger, true).
				Bind(
					restate.Reflect(
						&portallocator.PortAllocator{},
					),
				).
				Bind(
					restate.Reflect(
						&networkidallocator.NetworkIDAllocator{},
					),
				).
				Bind(
					restate.Reflect(
						&ipallocator.IPAllocator{},
					),
				)

			err := server.Start(c.Context, cfg.addr)
			if err != nil {
				return fmt.Errorf("failed to start server: %w", err)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
