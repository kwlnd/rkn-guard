package logger

import (
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger дополняет zerolog.Logger настройками проекта.
type Logger struct {
	zerolog.Logger
}

// ColorEnabled сообщает, можно ли красить вывод в файл f.
func ColorEnabled(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	return isatty.IsTerminal(f.Fd())
}

// New создаёт журнал для человека: без меток времени, с короткой меткой уровня.
// verbose включает отладочные сообщения и полное время.
func New(verbose bool) *Logger {
	color := ColorEnabled(os.Stderr)
	paint := func(code, text string) string {
		if !color {
			return text
		}
		return "\033[" + code + "m" + text + "\033[0m"
	}
	output := zerolog.ConsoleWriter{Out: os.Stderr, NoColor: !color}
	if verbose {
		output.TimeFormat = "15:04:05.000"
	} else {
		output.PartsExclude = []string{zerolog.TimestampFieldName}
	}
	output.FormatLevel = func(i interface{}) string {
		switch fmt.Sprint(i) {
		case "debug", "trace":
			return paint("90", "·")
		case "warn":
			return paint("33", "!")
		case "error", "fatal", "panic":
			return paint("31", "✗")
		}
		return paint("36", "•")
	}
	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}
	return &Logger{zerolog.New(output).Level(level).With().Timestamp().Logger()}
}

// SetGlobalLogger задаёт общий журнал приложения.
func SetGlobalLogger(logger *Logger) {
	log.Logger = logger.Logger
}

// Global возвращает общий журнал приложения.
func Global() *Logger {
	return &Logger{log.Logger}
}
