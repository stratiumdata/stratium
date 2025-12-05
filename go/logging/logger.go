package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"stratium/features"
	"sync"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelStartup // Special level for startup messages only
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorReset   = "\033[0m"
)

// Logger is the main logger interface
type Logger struct {
	infoLogger    *log.Logger
	warnLogger    *log.Logger
	errorLogger   *log.Logger
	debugLogger   *log.Logger
	startupLogger *log.Logger
	minLevel      LogLevel
	mu            sync.Mutex
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// GetLogger returns the singleton logger instance
func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger()
	})
	return defaultLogger
}

// NewLogger creates a new logger with appropriate settings based on feature flags
func NewLogger() *Logger {
	var minLevel LogLevel
	var output io.Writer = os.Stdout

	// If not in full logging mode (i.e., demo mode), only show startup messages
	if !features.ShouldEnableFullLogging() {
		minLevel = LevelStartup
	} else {
		minLevel = LevelDebug
	}

	logger := &Logger{
		infoLogger:    log.New(output, "INFO: ", log.Ldate|log.Ltime),
		warnLogger:    log.New(output, "WARN: ", log.Ldate|log.Ltime),
		errorLogger:   log.New(output, "ERROR: ", log.Ldate|log.Ltime),
		debugLogger:   log.New(output, "DEBUG: ", log.Ldate|log.Ltime),
		startupLogger: log.New(output, "STARTUP: ", log.Ldate|log.Ltime),
		minLevel:      minLevel,
	}

	return logger
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// If not in full logging mode (i.e., demo mode), only show startup messages
	if !features.ShouldEnableFullLogging() {
		l.minLevel = LevelStartup
	} else {
		l.minLevel = level
	}
}

// Debug logs a debug message (only in full logging mode)
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.minLevel <= LevelDebug {
		l.mu.Lock()
		defer l.mu.Unlock()
		s := fmt.Sprintf(format, v...)
		l.debugLogger.Printf("%s%s%s", colorCyan, s, colorReset)
	}
}

// Info logs an info message (only in full logging mode)
func (l *Logger) Info(format string, v ...interface{}) {
	if l.minLevel <= LevelInfo {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.infoLogger.Printf(format, v...)
	}
}

// Warn logs a warning message (only in full logging mode)
func (l *Logger) Warn(format string, v ...interface{}) {
	if l.minLevel <= LevelWarn {
		l.mu.Lock()
		defer l.mu.Unlock()
		s := fmt.Sprintf(format, v...)
		l.warnLogger.Printf("%s%s%s", colorYellow, s, colorReset)
	}
}

// Error logs an error message (always logged)
func (l *Logger) Error(format string, v ...interface{}) {
	if l.minLevel <= LevelError {
		l.mu.Lock()
		defer l.mu.Unlock()
		s := fmt.Sprintf(format, v...)
		l.errorLogger.Printf("%s%s%s", colorRed, s, colorReset)
	}
}

// Startup logs a startup message (always logged, even in minimal mode)
func (l *Logger) Startup(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := fmt.Sprintf(format, v...)
	l.startupLogger.Printf("%s%s%s", colorMagenta, s, colorReset)
}

// PrintBuildInfo prints build and feature flag information at startup
func (l *Logger) PrintBuildInfo(serviceName, serviceVersion string) {
	buildInfo := features.GetBuildInfo()

	l.Startup("=================================================")
	l.Startup("Service: %s v%s", serviceName, serviceVersion)
	l.Startup("Build Mode: %s", buildInfo["mode"])
	l.Startup("Build Version: %s", buildInfo["version"])
	l.Startup("Build Time: %s", buildInfo["buildTime"])

	enabledFeatures := features.GetEnabledFeatures()
	if len(enabledFeatures) > 0 {
		l.Startup("Enabled Features: %v", enabledFeatures)
	} else {
		l.Startup("Enabled Features: none (production defaults)")
	}

	l.Startup("Full Logging: %v", features.ShouldEnableFullLogging())
	l.Startup("Metrics: %v", features.ShouldEnableMetrics())
	l.Startup("Observability: %v", features.ShouldEnableObservability())
	l.Startup("Rate Limiting: %v", features.ShouldEnableRateLimiting())
	l.Startup("Caching: %v", features.ShouldEnableCaching())
	l.Startup("Short Timeouts: %v", features.ShouldUseShortTimeouts())
	l.Startup("=================================================")
}

// Convenience functions that use the default logger
func Debug(format string, v ...interface{}) {
	GetLogger().Debug(format, v...)
}

func Info(format string, v ...interface{}) {
	GetLogger().Info(format, v...)
}

func Warn(format string, v ...interface{}) {
	GetLogger().Warn(format, v...)
}

func Error(format string, v ...interface{}) {
	GetLogger().Error(format, v...)
}

func Startup(format string, v ...interface{}) {
	GetLogger().Startup(format, v...)
}

func PrintBuildInfo(serviceName, serviceVersion string) {
	GetLogger().PrintBuildInfo(serviceName, serviceVersion)
}

// LoggingMode returns a string describing the current logging mode
func LoggingMode() string {
	if features.ShouldEnableFullLogging() {
		return "full"
	}
	return "minimal (startup only)"
}

// Printf provides a simple printf-style logging for backward compatibility
func Printf(format string, v ...interface{}) {
	if features.ShouldEnableFullLogging() {
		fmt.Printf(format+"\n", v...)
	}
}
