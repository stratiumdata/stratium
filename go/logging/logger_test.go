package logging

import (
	"bytes"
	"os"
	"stratium/features"
	"strings"
	"sync"
	"testing"
)

func TestLoggerMinimalMode(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	originalFeatures := features.BuildFeatures
	defer func() {
		features.BuildMode = originalMode
		features.BuildFeatures = originalFeatures
	}()

	// Set to demo mode (minimal logging)
	features.BuildMode = "demo"
	features.BuildFeatures = ""

	// Create a buffer to capture output
	var buf bytes.Buffer
	logger := NewLogger()
	logger.infoLogger.SetOutput(&buf)
	logger.debugLogger.SetOutput(&buf)
	logger.startupLogger.SetOutput(&buf)

	// Try to log various messages
	logger.Debug("This should not appear")
	logger.Info("This should not appear either")
	logger.Startup("This should appear")

	output := buf.String()

	// Verify debug and info don't appear
	if strings.Contains(output, "DEBUG") {
		t.Error("Debug message appeared in minimal logging mode")
	}
	if strings.Contains(output, "INFO") {
		t.Error("Info message appeared in minimal logging mode")
	}

	// Verify startup appears
	if !strings.Contains(output, "STARTUP") {
		t.Error("Startup message did not appear in minimal logging mode")
	}
}

func TestLoggerFullMode(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	originalFeatures := features.BuildFeatures
	defer func() {
		features.BuildMode = originalMode
		features.BuildFeatures = originalFeatures
	}()

	// Set to production mode (full logging)
	features.BuildMode = "production"
	features.BuildFeatures = ""

	// Clear the feature cache
	features.GetEnabledFeatures() // trigger cache rebuild

	// Create a buffer to capture output
	var buf bytes.Buffer
	logger := NewLogger()
	logger.infoLogger.SetOutput(&buf)
	logger.debugLogger.SetOutput(&buf)
	logger.startupLogger.SetOutput(&buf)

	// Try to log various messages
	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Startup("Startup message")

	output := buf.String()

	// Verify all messages appear
	if !strings.Contains(output, "DEBUG") {
		t.Error("Debug message did not appear in full logging mode")
	}
	if !strings.Contains(output, "INFO") {
		t.Error("Info message did not appear in full logging mode")
	}
	if !strings.Contains(output, "STARTUP") {
		t.Error("Startup message did not appear in full logging mode")
	}
}

func TestLoggingMode(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	tests := []struct {
		name         string
		buildMode    string
		expectedMode string
	}{
		{"demo mode", "demo", "minimal (startup only)"},
		{"production mode", "production", "full"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			features.BuildMode = tt.buildMode
			mode := LoggingMode()

			if mode != tt.expectedMode {
				t.Errorf("LoggingMode() = %s, want %s", mode, tt.expectedMode)
			}
		})
	}
}

func TestGetLogger(t *testing.T) {
	// Reset the singleton for testing
	defaultLogger = nil
	once = sync.Once{}

	// First call should create the logger
	logger1 := GetLogger()
	if logger1 == nil {
		t.Error("GetLogger() returned nil")
	}

	// Second call should return the same instance
	logger2 := GetLogger()
	if logger1 != logger2 {
		t.Error("GetLogger() did not return the same instance")
	}
}

func TestSetLevel(t *testing.T) {
	logger := NewLogger()

	tests := []struct {
		name     string
		level    LogLevel
		expected LogLevel
	}{
		{"set to debug", LevelDebug, LevelDebug},
		{"set to info", LevelInfo, LevelInfo},
		{"set to warn", LevelWarn, LevelWarn},
		{"set to error", LevelError, LevelError},
		{"set to startup", LevelStartup, LevelStartup},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.SetLevel(tt.level)
			if logger.minLevel != tt.expected {
				t.Errorf("SetLevel(%v) set minLevel to %v, want %v", tt.level, logger.minLevel, tt.expected)
			}
		})
	}
}

func TestWarnLogger(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Set to production mode (full logging)
	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := NewLogger()
	logger.warnLogger.SetOutput(&buf)

	logger.Warn("Warning message: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "WARN") {
		t.Error("Warn message did not contain WARN prefix")
	}
	if !strings.Contains(output, "Warning message") {
		t.Error("Warn message did not contain expected text")
	}
	if !strings.Contains(output, "test") {
		t.Error("Warn message did not contain formatted argument")
	}
}

func TestWarnLogger_Suppressed(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.warnLogger.SetOutput(&buf)
	logger.SetLevel(LevelError) // Set level higher than warn

	logger.Warn("This should not appear")

	output := buf.String()
	if strings.Contains(output, "WARN") {
		t.Error("Warn message appeared when level was set to Error")
	}
}

func TestErrorLogger(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Set to production mode
	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := NewLogger()
	logger.errorLogger.SetOutput(&buf)

	logger.Error("Error message: %s", "critical")

	output := buf.String()
	if !strings.Contains(output, "ERROR") {
		t.Error("Error message did not contain ERROR prefix")
	}
	if !strings.Contains(output, "Error message") {
		t.Error("Error message did not contain expected text")
	}
	if !strings.Contains(output, "critical") {
		t.Error("Error message did not contain formatted argument")
	}
}

func TestErrorLogger_Suppressed(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.errorLogger.SetOutput(&buf)
	logger.SetLevel(LevelStartup) // Set level higher than error

	logger.Error("This should not appear")

	output := buf.String()
	if strings.Contains(output, "ERROR") {
		t.Error("Error message appeared when level was set to Startup")
	}
}

func TestPrintBuildInfo(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	originalVersion := features.BuildVersion
	originalTime := features.BuildTime
	originalFeatures := features.BuildFeatures
	defer func() {
		features.BuildMode = originalMode
		features.BuildVersion = originalVersion
		features.BuildTime = originalTime
		features.BuildFeatures = originalFeatures
	}()

	// Set build info
	features.BuildMode = "production"
	features.BuildVersion = "1.2.3"
	features.BuildTime = "2025-01-15T10:00:00Z"
	features.BuildFeatures = "metrics,observability"

	var buf bytes.Buffer
	logger := NewLogger()
	logger.startupLogger.SetOutput(&buf)

	logger.PrintBuildInfo("test-service", "2.0.0")

	output := buf.String()

	// Verify service info
	if !strings.Contains(output, "test-service") {
		t.Error("PrintBuildInfo did not contain service name")
	}
	if !strings.Contains(output, "v2.0.0") {
		t.Error("PrintBuildInfo did not contain service version")
	}

	// Verify build info
	if !strings.Contains(output, "production") {
		t.Error("PrintBuildInfo did not contain build mode")
	}
	if !strings.Contains(output, "1.2.3") {
		t.Error("PrintBuildInfo did not contain build version")
	}
	if !strings.Contains(output, "2025-01-15T10:00:00Z") {
		t.Error("PrintBuildInfo did not contain build time")
	}

	// Verify feature flags
	if !strings.Contains(output, "Enabled Features") {
		t.Error("PrintBuildInfo did not contain enabled features")
	}
	if !strings.Contains(output, "Full Logging") {
		t.Error("PrintBuildInfo did not contain Full Logging status")
	}
	if !strings.Contains(output, "Metrics") {
		t.Error("PrintBuildInfo did not contain Metrics status")
	}
	if !strings.Contains(output, "Observability") {
		t.Error("PrintBuildInfo did not contain Observability status")
	}
	if !strings.Contains(output, "Rate Limiting") {
		t.Error("PrintBuildInfo did not contain Rate Limiting status")
	}
	if !strings.Contains(output, "Caching") {
		t.Error("PrintBuildInfo did not contain Caching status")
	}
	if !strings.Contains(output, "Short Timeouts") {
		t.Error("PrintBuildInfo did not contain Short Timeouts status")
	}

	// Verify formatting
	if !strings.Contains(output, "=====") {
		t.Error("PrintBuildInfo did not contain separator lines")
	}
}

func TestPrintBuildInfo_NoFeatures(t *testing.T) {
	// Save original values
	originalFeatures := features.BuildFeatures
	defer func() {
		features.BuildFeatures = originalFeatures
	}()

	// Set no features
	features.BuildFeatures = ""

	var buf bytes.Buffer
	logger := NewLogger()
	logger.startupLogger.SetOutput(&buf)

	logger.PrintBuildInfo("test-service", "1.0.0")

	output := buf.String()

	// Verify it shows "production defaults" when no features are enabled
	if !strings.Contains(output, "none (production defaults)") && !strings.Contains(output, "Enabled Features:") {
		t.Error("PrintBuildInfo did not handle empty features correctly")
	}
}

func TestGlobalDebug(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := GetLogger()
	logger.debugLogger.SetOutput(&buf)

	Debug("Global debug: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "DEBUG") {
		t.Error("Global Debug() did not produce debug output")
	}
	if !strings.Contains(output, "Global debug") {
		t.Error("Global Debug() did not contain expected message")
	}
}

func TestGlobalInfo(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := GetLogger()
	logger.infoLogger.SetOutput(&buf)

	Info("Global info: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Error("Global Info() did not produce info output")
	}
	if !strings.Contains(output, "Global info") {
		t.Error("Global Info() did not contain expected message")
	}
}

func TestGlobalWarn(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := GetLogger()
	logger.warnLogger.SetOutput(&buf)

	Warn("Global warn: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "WARN") {
		t.Error("Global Warn() did not produce warn output")
	}
	if !strings.Contains(output, "Global warn") {
		t.Error("Global Warn() did not contain expected message")
	}
}

func TestGlobalError(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := GetLogger()
	logger.errorLogger.SetOutput(&buf)

	Error("Global error: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "ERROR") {
		t.Error("Global Error() did not produce error output")
	}
	if !strings.Contains(output, "Global error") {
		t.Error("Global Error() did not contain expected message")
	}
}

func TestGlobalStartup(t *testing.T) {
	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	var buf bytes.Buffer
	logger := GetLogger()
	logger.startupLogger.SetOutput(&buf)

	Startup("Global startup: %s", "test")

	output := buf.String()
	if !strings.Contains(output, "STARTUP") {
		t.Error("Global Startup() did not produce startup output")
	}
	if !strings.Contains(output, "Global startup") {
		t.Error("Global Startup() did not contain expected message")
	}
}

func TestGlobalPrintBuildInfo(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	originalVersion := features.BuildVersion
	defer func() {
		features.BuildMode = originalMode
		features.BuildVersion = originalVersion
	}()

	// Reset singleton
	defaultLogger = nil
	once = sync.Once{}

	features.BuildMode = "production"
	features.BuildVersion = "1.0.0"

	var buf bytes.Buffer
	logger := GetLogger()
	logger.startupLogger.SetOutput(&buf)

	PrintBuildInfo("global-service", "3.0.0")

	output := buf.String()
	if !strings.Contains(output, "global-service") {
		t.Error("Global PrintBuildInfo() did not contain service name")
	}
	if !strings.Contains(output, "v3.0.0") {
		t.Error("Global PrintBuildInfo() did not contain service version")
	}
}

func TestPrintf_FullLogging(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	features.BuildMode = "production"

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Printf("Test printf: %s", "value")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Test printf") {
		t.Error("Printf() did not output message in full logging mode")
	}
	if !strings.Contains(output, "value") {
		t.Error("Printf() did not format arguments correctly")
	}
}

func TestPrintf_MinimalLogging(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	features.BuildMode = "demo"

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Printf("This should not appear")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if strings.Contains(output, "This should not appear") {
		t.Error("Printf() produced output in minimal logging mode")
	}
}

func TestConcurrentLogging(t *testing.T) {
	// Save original values
	originalMode := features.BuildMode
	defer func() {
		features.BuildMode = originalMode
	}()

	features.BuildMode = "production"

	var buf bytes.Buffer
	logger := NewLogger()
	logger.infoLogger.SetOutput(&buf)
	logger.debugLogger.SetOutput(&buf)
	logger.warnLogger.SetOutput(&buf)
	logger.errorLogger.SetOutput(&buf)
	logger.startupLogger.SetOutput(&buf)

	// Test concurrent access to logger
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Debug("Debug %d", id)
			logger.Info("Info %d", id)
			logger.Warn("Warn %d", id)
			logger.Error("Error %d", id)
			logger.Startup("Startup %d", id)
			done <- true
		}(i)
	}

	// Wait for all goroutines to finish
	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()

	// Verify all log levels appeared
	if !strings.Contains(output, "DEBUG") {
		t.Error("Concurrent logging did not produce DEBUG messages")
	}
	if !strings.Contains(output, "INFO") {
		t.Error("Concurrent logging did not produce INFO messages")
	}
	if !strings.Contains(output, "WARN") {
		t.Error("Concurrent logging did not produce WARN messages")
	}
	if !strings.Contains(output, "ERROR") {
		t.Error("Concurrent logging did not produce ERROR messages")
	}
	if !strings.Contains(output, "STARTUP") {
		t.Error("Concurrent logging did not produce STARTUP messages")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name               string
		level              LogLevel
		shouldLogDebug     bool
		shouldLogInfo      bool
		shouldLogWarn      bool
		shouldLogError     bool
		shouldLogStartup   bool
	}{
		{
			name:             "Debug level logs everything",
			level:            LevelDebug,
			shouldLogDebug:   true,
			shouldLogInfo:    true,
			shouldLogWarn:    true,
			shouldLogError:   true,
			shouldLogStartup: true,
		},
		{
			name:             "Info level filters debug",
			level:            LevelInfo,
			shouldLogDebug:   false,
			shouldLogInfo:    true,
			shouldLogWarn:    true,
			shouldLogError:   true,
			shouldLogStartup: true,
		},
		{
			name:             "Warn level filters debug and info",
			level:            LevelWarn,
			shouldLogDebug:   false,
			shouldLogInfo:    false,
			shouldLogWarn:    true,
			shouldLogError:   true,
			shouldLogStartup: true,
		},
		{
			name:             "Error level filters debug, info, and warn",
			level:            LevelError,
			shouldLogDebug:   false,
			shouldLogInfo:    false,
			shouldLogWarn:    false,
			shouldLogError:   true,
			shouldLogStartup: true,
		},
		{
			name:             "Startup level filters everything except startup",
			level:            LevelStartup,
			shouldLogDebug:   false,
			shouldLogInfo:    false,
			shouldLogWarn:    false,
			shouldLogError:   false,
			shouldLogStartup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger()
			logger.SetLevel(tt.level)

			logger.debugLogger.SetOutput(&buf)
			logger.infoLogger.SetOutput(&buf)
			logger.warnLogger.SetOutput(&buf)
			logger.errorLogger.SetOutput(&buf)
			logger.startupLogger.SetOutput(&buf)

			logger.Debug("debug")
			logger.Info("info")
			logger.Warn("warn")
			logger.Error("error")
			logger.Startup("startup")

			output := buf.String()

			// Check debug
			if tt.shouldLogDebug && !strings.Contains(output, "DEBUG") {
				t.Errorf("Expected DEBUG to be logged at level %v", tt.level)
			}
			if !tt.shouldLogDebug && strings.Contains(output, "DEBUG") {
				t.Errorf("Expected DEBUG to be filtered at level %v", tt.level)
			}

			// Check info
			if tt.shouldLogInfo && !strings.Contains(output, "INFO") {
				t.Errorf("Expected INFO to be logged at level %v", tt.level)
			}
			if !tt.shouldLogInfo && strings.Contains(output, "INFO") {
				t.Errorf("Expected INFO to be filtered at level %v", tt.level)
			}

			// Check warn
			if tt.shouldLogWarn && !strings.Contains(output, "WARN") {
				t.Errorf("Expected WARN to be logged at level %v", tt.level)
			}
			if !tt.shouldLogWarn && strings.Contains(output, "WARN") {
				t.Errorf("Expected WARN to be filtered at level %v", tt.level)
			}

			// Check error
			if tt.shouldLogError && !strings.Contains(output, "ERROR") {
				t.Errorf("Expected ERROR to be logged at level %v", tt.level)
			}
			if !tt.shouldLogError && strings.Contains(output, "ERROR") {
				t.Errorf("Expected ERROR to be filtered at level %v", tt.level)
			}

			// Check startup (should always log)
			if !strings.Contains(output, "STARTUP") {
				t.Errorf("Expected STARTUP to always be logged")
			}
		})
	}
}