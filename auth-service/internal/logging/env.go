package logging

import (
	"log/slog"
	"os"
)

func FromEnv(service string) *LoggerConfig {
	return &LoggerConfig{
		Level:   getenv("LOG_LEVEL", "info"),
		Format:  getenv("LOG_FORMAT", "json"),
		Service: service,
	}
}

type LoggerConfig struct {
	Level, Format, Service string
}

func (c *LoggerConfig) Build() *slog.Logger {
	return New(Options{Level: c.Level, Format: c.Format, Service: c.Service})
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
