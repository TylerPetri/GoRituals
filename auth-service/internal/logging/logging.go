package logging

import (
	"log/slog"
	"os"
	"strings"
)

type Options struct {
	Level   string // "debug"|"info"|"warn"|"error"
	Format  string // "json"|"text"
	Service string
}

func New(opts Options) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(opts.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var h slog.Handler
	if strings.ToLower(opts.Format) == "text" {
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	l := slog.New(h)
	if opts.Service != "" {
		l = l.With("service", opts.Service)
	}
	return l
}
