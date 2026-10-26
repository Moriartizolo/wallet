package safelog

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// Logger is a thin zerolog wrapper that sanitizes every field before it is
// emitted. It intentionally has no API for writing raw JSON: all structured
// values pass through RedactMap first.
type Logger struct {
	zl      zerolog.Logger
	service string
}

// New creates a JSON logger writing to out. Invalid levels fall back to info.
func New(level, service string, out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		parsed = zerolog.InfoLevel
	}
	logger := zerolog.New(out).
		Level(parsed).
		With().
		Timestamp().
		Caller().
		Str("service", service).
		Logger()
	return &Logger{zl: logger, service: service}
}

// With returns a child logger with pre-sanitized context fields.
func (l *Logger) With(fields map[string]any) *Logger {
	if len(fields) == 0 {
		return l
	}
	return &Logger{
		zl:      l.zl.With().Fields(RedactMap(fields)).Logger(),
		service: l.service,
	}
}

func (l *Logger) Debug(message string, fields map[string]any) {
	l.emit(l.zl.Debug(), message, fields)
}

func (l *Logger) Info(message string, fields map[string]any) {
	l.emit(l.zl.Info(), message, fields)
}

func (l *Logger) Warn(message string, fields map[string]any) {
	l.emit(l.zl.Warn(), message, fields)
}

func (l *Logger) Error(message string, fields map[string]any) {
	l.emit(l.zl.Error(), message, fields)
}

// Err logs an error at error level. The error text is masked as well, in case a
// driver ever includes a card number in its error message.
func (l *Logger) Err(err error, message string, fields map[string]any) {
	copied := make(map[string]any, len(fields)+1)
	for key, value := range fields {
		copied[key] = value
	}
	if err != nil {
		copied["error"] = err
	}
	l.emit(l.zl.Error(), message, copied)
}

// Sampled logs high-volume events at info level.
func (l *Logger) Sampled(message string, fields map[string]any) {
	l.emit(l.zl.Info(), message, fields)
}

func (l *Logger) emit(event *zerolog.Event, message string, fields map[string]any) {
	if len(fields) > 0 {
		event = event.Fields(RedactMap(fields))
	}
	event.Msg(MaskString(message))
}
