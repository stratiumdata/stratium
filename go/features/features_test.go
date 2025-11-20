package features

import (
	"testing"
)

func TestIsEnabled(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		feature        string
		expectedResult bool
	}{
		{
			name:           "empty features",
			buildFeatures:  "",
			feature:        FeatureMetrics,
			expectedResult: false,
		},
		{
			name:           "single feature enabled",
			buildFeatures:  "metrics",
			feature:        FeatureMetrics,
			expectedResult: true,
		},
		{
			name:           "multiple features enabled",
			buildFeatures:  "metrics,observability,rate-limiting",
			feature:        FeatureObservability,
			expectedResult: true,
		},
		{
			name:           "feature not in list",
			buildFeatures:  "metrics,observability",
			feature:        FeatureRateLimiting,
			expectedResult: false,
		},
		{
			name:           "features with spaces",
			buildFeatures:  "metrics, observability, rate-limiting",
			feature:        FeatureObservability,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildFeatures = tt.buildFeatures
			result := IsEnabled(tt.feature)

			if result != tt.expectedResult {
				t.Errorf("IsEnabled(%s) = %v, want %v", tt.feature, result, tt.expectedResult)
			}
		})
	}
}

func TestIsDemoMode(t *testing.T) {
	// Save original value
	originalMode := BuildMode
	defer func() { BuildMode = originalMode }()

	tests := []struct {
		name           string
		buildMode      string
		expectedResult bool
	}{
		{"demo mode", "demo", true},
		{"Demo mode uppercase", "DEMO", true},
		{"production mode", "production", false},
		{"development mode", "development", false},
		{"empty mode", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildMode = tt.buildMode
			result := IsDemoMode()

			if result != tt.expectedResult {
				t.Errorf("IsDemoMode() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestShouldEnableFullLogging(t *testing.T) {
	// Save original values
	originalMode := BuildMode
	originalFeatures := BuildFeatures
	defer func() {
		BuildMode = originalMode
		BuildFeatures = originalFeatures
	}()

	tests := []struct {
		name           string
		buildMode      string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "demo mode without full-logging flag",
			buildMode:      "demo",
			buildFeatures:  "",
			expectedResult: false,
		},
		{
			name:           "demo mode with full-logging flag",
			buildMode:      "demo",
			buildFeatures:  "full-logging",
			expectedResult: true,
		},
		{
			name:           "production mode without full-logging flag",
			buildMode:      "production",
			buildFeatures:  "",
			expectedResult: true,
		},
		{
			name:           "development mode without full-logging flag",
			buildMode:      "development",
			buildFeatures:  "",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildMode = tt.buildMode
			BuildFeatures = tt.buildFeatures
			result := ShouldEnableFullLogging()

			if result != tt.expectedResult {
				t.Errorf("ShouldEnableFullLogging() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestShouldUseShortTimeouts(t *testing.T) {
	// Save original values
	originalMode := BuildMode
	originalFeatures := BuildFeatures
	defer func() {
		BuildMode = originalMode
		BuildFeatures = originalFeatures
	}()

	tests := []struct {
		name           string
		buildMode      string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "demo mode",
			buildMode:      "demo",
			buildFeatures:  "",
			expectedResult: true,
		},
		{
			name:           "production mode with short-timeouts flag",
			buildMode:      "production",
			buildFeatures:  "short-timeouts",
			expectedResult: true,
		},
		{
			name:           "production mode without short-timeouts flag",
			buildMode:      "production",
			buildFeatures:  "",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildMode = tt.buildMode
			BuildFeatures = tt.buildFeatures
			result := ShouldUseShortTimeouts()

			if result != tt.expectedResult {
				t.Errorf("ShouldUseShortTimeouts() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestGetEnabledFeatures(t *testing.T) {
	// Save original value
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		expectedLength int
	}{
		{"empty features", "", 0},
		{"single feature", "metrics", 1},
		{"multiple features", "metrics,observability,rate-limiting", 3},
		{"features with spaces", "metrics, observability, rate-limiting", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildFeatures = tt.buildFeatures
			result := GetEnabledFeatures()

			if len(result) != tt.expectedLength {
				t.Errorf("GetEnabledFeatures() returned %d features, want %d", len(result), tt.expectedLength)
			}
		})
	}
}

func TestShouldEnableCaching(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "caching disabled by default",
			buildFeatures:  "",
			expectedResult: false,
		},
		{
			name:           "caching enabled with flag",
			buildFeatures:  "caching",
			expectedResult: true,
		},
		{
			name:           "caching with other features",
			buildFeatures:  "metrics,caching,observability",
			expectedResult: true,
		},
		{
			name:           "caching not in list",
			buildFeatures:  "metrics,observability",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildFeatures = tt.buildFeatures
			result := ShouldEnableCaching()

			if result != tt.expectedResult {
				t.Errorf("ShouldEnableCaching() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestShouldEnableMetrics(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "metrics disabled by default",
			buildFeatures:  "",
			expectedResult: false,
		},
		{
			name:           "metrics enabled with flag",
			buildFeatures:  "metrics",
			expectedResult: true,
		},
		{
			name:           "metrics with other features",
			buildFeatures:  "observability,metrics,rate-limiting",
			expectedResult: true,
		},
		{
			name:           "metrics not in list",
			buildFeatures:  "observability,rate-limiting",
			expectedResult: false,
		},
		{
			name:           "metrics with spaces in list",
			buildFeatures:  "observability, metrics, rate-limiting",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildFeatures = tt.buildFeatures
			result := ShouldEnableMetrics()

			if result != tt.expectedResult {
				t.Errorf("ShouldEnableMetrics() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestShouldEnableObservability(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "observability disabled by default",
			buildFeatures:  "",
			expectedResult: false,
		},
		{
			name:           "observability enabled with flag",
			buildFeatures:  "observability",
			expectedResult: true,
		},
		{
			name:           "observability with other features",
			buildFeatures:  "metrics,observability,rate-limiting",
			expectedResult: true,
		},
		{
			name:           "observability not in list",
			buildFeatures:  "metrics,rate-limiting",
			expectedResult: false,
		},
		{
			name:           "observability with spaces in list",
			buildFeatures:  "metrics, observability, rate-limiting",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildFeatures = tt.buildFeatures
			result := ShouldEnableObservability()

			if result != tt.expectedResult {
				t.Errorf("ShouldEnableObservability() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestShouldEnableRateLimiting(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	tests := []struct {
		name           string
		buildFeatures  string
		expectedResult bool
	}{
		{
			name:           "rate limiting disabled by default",
			buildFeatures:  "",
			expectedResult: false,
		},
		{
			name:           "rate limiting enabled with flag",
			buildFeatures:  "rate-limiting",
			expectedResult: true,
		},
		{
			name:           "rate limiting with other features",
			buildFeatures:  "metrics,observability,rate-limiting",
			expectedResult: true,
		},
		{
			name:           "rate limiting not in list",
			buildFeatures:  "metrics,observability",
			expectedResult: false,
		},
		{
			name:           "rate limiting with spaces in list",
			buildFeatures:  "metrics, observability, rate-limiting",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache
			cacheMux.Lock()
			featureCache = make(map[string]bool)
			cacheMux.Unlock()

			BuildFeatures = tt.buildFeatures
			result := ShouldEnableRateLimiting()

			if result != tt.expectedResult {
				t.Errorf("ShouldEnableRateLimiting() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestIsProductionMode(t *testing.T) {
	// Save original value
	originalMode := BuildMode
	defer func() { BuildMode = originalMode }()

	tests := []struct {
		name           string
		buildMode      string
		expectedResult bool
	}{
		{"production mode", "production", true},
		{"Production mode uppercase", "PRODUCTION", true},
		{"demo mode", "demo", false},
		{"development mode", "development", false},
		{"empty mode", "", false},
		{"unknown mode", "staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildMode = tt.buildMode
			result := IsProductionMode()

			if result != tt.expectedResult {
				t.Errorf("IsProductionMode() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestIsDevelopmentMode(t *testing.T) {
	// Save original value
	originalMode := BuildMode
	defer func() { BuildMode = originalMode }()

	tests := []struct {
		name           string
		buildMode      string
		expectedResult bool
	}{
		{"development mode", "development", true},
		{"Development mode uppercase", "DEVELOPMENT", true},
		{"demo mode", "demo", false},
		{"production mode", "production", false},
		{"empty mode", "", false},
		{"unknown mode", "staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildMode = tt.buildMode
			result := IsDevelopmentMode()

			if result != tt.expectedResult {
				t.Errorf("IsDevelopmentMode() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestGetBuildInfo(t *testing.T) {
	// Save original values
	originalMode := BuildMode
	originalVersion := BuildVersion
	originalTime := BuildTime
	originalFeatures := BuildFeatures
	defer func() {
		BuildMode = originalMode
		BuildVersion = originalVersion
		BuildTime = originalTime
		BuildFeatures = originalFeatures
	}()

	tests := []struct {
		name          string
		buildMode     string
		buildVersion  string
		buildTime     string
		buildFeatures string
	}{
		{
			name:          "production build",
			buildMode:     "production",
			buildVersion:  "1.0.0",
			buildTime:     "2025-01-15T10:00:00Z",
			buildFeatures: "metrics,observability",
		},
		{
			name:          "demo build",
			buildMode:     "demo",
			buildVersion:  "1.0.0-demo",
			buildTime:     "2025-01-15T11:00:00Z",
			buildFeatures: "short-timeouts",
		},
		{
			name:          "development build",
			buildMode:     "development",
			buildVersion:  "dev",
			buildTime:     "unknown",
			buildFeatures: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			BuildMode = tt.buildMode
			BuildVersion = tt.buildVersion
			BuildTime = tt.buildTime
			BuildFeatures = tt.buildFeatures

			result := GetBuildInfo()

			if result["mode"] != tt.buildMode {
				t.Errorf("GetBuildInfo()[\"mode\"] = %v, want %v", result["mode"], tt.buildMode)
			}
			if result["version"] != tt.buildVersion {
				t.Errorf("GetBuildInfo()[\"version\"] = %v, want %v", result["version"], tt.buildVersion)
			}
			if result["buildTime"] != tt.buildTime {
				t.Errorf("GetBuildInfo()[\"buildTime\"] = %v, want %v", result["buildTime"], tt.buildTime)
			}
			if result["features"] != tt.buildFeatures {
				t.Errorf("GetBuildInfo()[\"features\"] = %v, want %v", result["features"], tt.buildFeatures)
			}

			// Verify all expected keys are present
			expectedKeys := []string{"mode", "version", "buildTime", "features"}
			for _, key := range expectedKeys {
				if _, exists := result[key]; !exists {
					t.Errorf("GetBuildInfo() missing key: %s", key)
				}
			}

			// Verify no extra keys
			if len(result) != len(expectedKeys) {
				t.Errorf("GetBuildInfo() returned %d keys, want %d", len(result), len(expectedKeys))
			}
		})
	}
}

func TestFeatureCaching(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	// Clear cache
	cacheMux.Lock()
	featureCache = make(map[string]bool)
	cacheMux.Unlock()

	// Set features
	BuildFeatures = "metrics,observability"

	// First call - should cache the result
	result1 := IsEnabled(FeatureMetrics)
	if !result1 {
		t.Error("First call: IsEnabled(FeatureMetrics) should be true")
	}

	// Change BuildFeatures (but cache should still be used)
	BuildFeatures = ""

	// Second call - should return cached result (true), not the new value
	result2 := IsEnabled(FeatureMetrics)
	if !result2 {
		t.Error("Second call: IsEnabled(FeatureMetrics) should still be true (from cache)")
	}

	// Clear cache
	cacheMux.Lock()
	featureCache = make(map[string]bool)
	cacheMux.Unlock()

	// Third call - should now reflect the new BuildFeatures value
	result3 := IsEnabled(FeatureMetrics)
	if result3 {
		t.Error("Third call after cache clear: IsEnabled(FeatureMetrics) should be false")
	}
}

func TestConcurrentFeatureAccess(t *testing.T) {
	// Save original values
	originalFeatures := BuildFeatures
	defer func() { BuildFeatures = originalFeatures }()

	// Clear cache
	cacheMux.Lock()
	featureCache = make(map[string]bool)
	cacheMux.Unlock()

	BuildFeatures = "metrics,observability,rate-limiting,caching"

	// Test concurrent access to feature flags
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			// Each goroutine calls multiple feature flag functions
			_ = ShouldEnableMetrics()
			_ = ShouldEnableObservability()
			_ = ShouldEnableRateLimiting()
			_ = ShouldEnableCaching()
			_ = ShouldUseShortTimeouts()
			_ = ShouldEnableFullLogging()
			done <- true
		}()
	}

	// Wait for all goroutines to finish
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify that cache is populated correctly
	cacheMux.RLock()
	defer cacheMux.RUnlock()

	if !featureCache[FeatureMetrics] {
		t.Error("Cache should have metrics=true")
	}
	if !featureCache[FeatureObservability] {
		t.Error("Cache should have observability=true")
	}
	if !featureCache[FeatureRateLimiting] {
		t.Error("Cache should have rate-limiting=true")
	}
	if !featureCache[FeatureCaching] {
		t.Error("Cache should have caching=true")
	}
}