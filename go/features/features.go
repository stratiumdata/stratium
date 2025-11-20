package features

import (
	"strings"
	"sync"
)

// Build-time variables set via ldflags
var (
	// BuildMode indicates the build mode (demo, production, development)
	BuildMode = "production"

	// BuildFeatures is a comma-separated list of enabled features
	// Can be overridden at build time with:
	// -ldflags "-X stratium/features.BuildFeatures=feature1,feature2"
	BuildFeatures = ""

	// BuildVersion is the version of the build
	BuildVersion = "dev"

	// BuildTime is the time the binary was built
	BuildTime = "unknown"
)

// Feature names
const (
	FeatureFullLogging     = "full-logging"
	FeatureMetrics         = "metrics"
	FeatureObservability   = "observability"
	FeatureRateLimiting    = "rate-limiting"
	FeatureShortTimeouts   = "short-timeouts"
	FeatureCaching         = "caching"
)

var (
	featureCache = make(map[string]bool)
	cacheMux     sync.RWMutex
)

// IsEnabled checks if a feature is enabled based on build-time flags
func IsEnabled(feature string) bool {
	cacheMux.RLock()
	if enabled, found := featureCache[feature]; found {
		cacheMux.RUnlock()
		return enabled
	}
	cacheMux.RUnlock()

	// Parse features from BuildFeatures
	enabled := false
	if BuildFeatures != "" {
		features := strings.Split(BuildFeatures, ",")
		for _, f := range features {
			if strings.TrimSpace(f) == feature {
				enabled = true
				break
			}
		}
	}

	// Cache the result
	cacheMux.Lock()
	featureCache[feature] = enabled
	cacheMux.Unlock()

	return enabled
}

// IsDemoMode returns true if the build is in demo mode
func IsDemoMode() bool {
	return strings.ToLower(BuildMode) == "demo"
}

// IsProductionMode returns true if the build is in production mode
func IsProductionMode() bool {
	return strings.ToLower(BuildMode) == "production"
}

// IsDevelopmentMode returns true if the build is in development mode
func IsDevelopmentMode() bool {
	return strings.ToLower(BuildMode) == "development"
}

// GetEnabledFeatures returns a slice of all enabled features
func GetEnabledFeatures() []string {
	if BuildFeatures == "" {
		return []string{}
	}
	features := strings.Split(BuildFeatures, ",")
	result := make([]string, 0, len(features))
	for _, f := range features {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// ShouldEnableFullLogging returns true if full logging should be enabled
func ShouldEnableFullLogging() bool {
	// Full logging is enabled if:
	// 1. Explicitly enabled via feature flag, OR
	// 2. Not in demo mode (demo mode has minimal logging)
	return IsEnabled(FeatureFullLogging) || !IsDemoMode()
}

// ShouldEnableMetrics returns true if metrics should be enabled
func ShouldEnableMetrics() bool {
	return IsEnabled(FeatureMetrics)
}

// ShouldEnableObservability returns true if observability should be enabled
func ShouldEnableObservability() bool {
	return IsEnabled(FeatureObservability)
}

// ShouldEnableRateLimiting returns true if rate limiting should be enabled
func ShouldEnableRateLimiting() bool {
	return IsEnabled(FeatureRateLimiting)
}

// ShouldUseShortTimeouts returns true if short timeouts should be used
func ShouldUseShortTimeouts() bool {
	return IsEnabled(FeatureShortTimeouts) || IsDemoMode()
}

// ShouldEnableCaching returns true if advanced caching should be enabled
func ShouldEnableCaching() bool {
	return IsEnabled(FeatureCaching)
}

// GetBuildInfo returns build information as a map
func GetBuildInfo() map[string]string {
	return map[string]string{
		"mode":     BuildMode,
		"version":  BuildVersion,
		"buildTime": BuildTime,
		"features": BuildFeatures,
	}
}