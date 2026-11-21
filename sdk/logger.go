package sdk

import (
	"context"
	"log/slog"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type LogFields map[string]any

// Logger is a small, implementation-neutral logging interface.
// Adapters can forward logs to slog, zerolog, logrus, zap or a custom logger.
type Logger interface {
	Log(level LogLevel, event, message string, fields LogFields)
}

// LoggerFunc adapts a plain function to Logger.
type LoggerFunc func(level LogLevel, event, message string, fields LogFields)

func (f LoggerFunc) Log(level LogLevel, event, message string, fields LogFields) {
	if f != nil {
		f(level, event, message, fields)
	}
}

// SlogLogger adapts a standard library slog.Logger.
type SlogLogger struct {
	Logger *slog.Logger
}

func NewSlogLogger(logger *slog.Logger) Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return &SlogLogger{Logger: logger}
}

func (l *SlogLogger) Log(level LogLevel, event, message string, fields LogFields) {
	if l == nil || l.Logger == nil {
		return
	}
	attrs := make([]any, 0, len(fields)+1)
	attrs = append(attrs, "event", event)
	for key, value := range fields {
		attrs = append(attrs, key, value)
	}

	var slogLevel slog.Level
	switch level {
	case LogLevelDebug:
		slogLevel = slog.LevelDebug
	case LogLevelWarn:
		slogLevel = slog.LevelWarn
	case LogLevelError:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	l.Logger.Log(context.Background(), slogLevel, message, attrs...)
}

// NopLogger discards SDK log messages.
type NopLogger struct{}

func (NopLogger) Log(LogLevel, string, string, LogFields) {}
