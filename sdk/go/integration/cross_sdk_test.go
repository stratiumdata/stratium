package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type sdkRequest struct {
	Plaintext    string `json:"plaintext,omitempty"`
	Ztdf         string `json:"ztdf,omitempty"`
	Filename     string `json:"filename,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
	Resource     string `json:"resource,omitempty"`
	PolicyBase64 string `json:"policyBase64,omitempty"`
}

type sdkResponse struct {
	Ztdf      string `json:"ztdf,omitempty"`
	Plaintext string `json:"plaintext,omitempty"`
}

type sdkRunner struct {
	name       string
	buildCmd   func(mode string) *exec.Cmd
	env        []string
	javaRunner bool
}

type integrationConfig struct {
	resource     string
	filename     string
	contentType  string
	policyBase64 string
	goKeyDir     string
	jsKeyDir     string
}

func TestCrossSdkPayloadCompatibility(t *testing.T) {
	paths := resolvePaths(t)
	cfg, skipReason := loadIntegrationConfig(paths)
	if skipReason != "" {
		t.Skip(skipReason)
	}

	fmt.Printf("[cross-sdk] env KEY_ACCESS_URL=%s KEY_ACCESS_URI=%s KEY_MANAGER_URL=%s KEY_MANAGER_URI=%s\n",
		os.Getenv("STRATIUM_KEY_ACCESS_URL"),
		os.Getenv("STRATIUM_KEY_ACCESS_URI"),
		os.Getenv("STRATIUM_KEY_MANAGER_URL"),
		os.Getenv("STRATIUM_KEY_MANAGER_URI"))
	fmt.Printf("[cross-sdk] key dirs go=%s js=%s subject=%s policyLen=%d\n",
		os.Getenv("STRATIUM_GO_KEY_DIR"),
		os.Getenv("STRATIUM_JS_KEY_DIR"),
		os.Getenv("STRATIUM_SUBJECT_ID"),
		len(cfg.policyBase64))

	artifactDir := filepath.Join(paths.repoRoot, "artifacts", "cross-sdk")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatalf("failed to create artifact directory: %v", err)
	}
	fmt.Printf("[cross-sdk] writing artifacts to %s\n", artifactDir)

	runners := map[string]sdkRunner{
		"go": {
			name: "go",
			buildCmd: func(mode string) *exec.Cmd {
				cmd := exec.Command("go", "run", "./cmd/crosssdk", mode)
				cmd.Dir = paths.goDir
				return cmd
			},
			env: []string{"STRATIUM_GO_KEY_DIR=" + cfg.goKeyDir, "STRATIUM_POLICY_BASE64=" + cfg.policyBase64},
		},
		"java": {
			name: "java",
			buildCmd: func(mode string) *exec.Cmd {
				execName := "./gradlew"
				if runtime.GOOS == "windows" {
					execName = "gradlew.bat"
				}
				cmd := exec.Command(execName, "-q", "runCrossSdkTool", "--args="+mode)
				cmd.Dir = paths.javaDir
				return cmd
			},
			env:        []string{"STRATIUM_POLICY_BASE64=" + cfg.policyBase64},
			javaRunner: true,
		},
		"js": {
			name: "js",
			buildCmd: func(mode string) *exec.Cmd {
				cmd := exec.Command("node", "scripts/cross-sdk-tool.mjs", mode)
				cmd.Dir = paths.jsDir
				return cmd
			},
			env: []string{"STRATIUM_JS_KEY_DIR=" + cfg.jsKeyDir, "STRATIUM_POLICY_BASE64=" + cfg.policyBase64},
		},
	}

	combos := []struct {
		encryptor string
		decryptor string
	}{
		{"java", "js"},
		{"java", "go"},
		{"js", "java"},
		{"js", "go"},
		{"go", "java"},
		{"go", "js"},
	}

	for _, combo := range combos {
		combo := combo
		t.Run(fmt.Sprintf("%s_to_%s", combo.encryptor, combo.decryptor), func(t *testing.T) {
			comboName := fmt.Sprintf("%s_to_%s", combo.encryptor, combo.decryptor)
			fmt.Printf("[cross-sdk] testing %s\n", comboName)
			plaintext := []byte("Cross-SDK payload for " + combo.encryptor + "->" + combo.decryptor)

			req := sdkRequest{
				Plaintext:    base64.StdEncoding.EncodeToString(plaintext),
				Filename:     cfg.filename,
				ContentType:  cfg.contentType,
				Resource:     cfg.resource,
				PolicyBase64: cfg.policyBase64,
			}
			encResp := runSdkCommand(t, runners[combo.encryptor], "encrypt", req, paths)
			if encResp.Ztdf == "" {
				t.Fatalf("%s encrypt returned empty ZTDF", combo.encryptor)
			}

			ztdfBytes, err := base64.StdEncoding.DecodeString(encResp.Ztdf)
			if err != nil {
				t.Fatalf("failed to decode ZTDF from %s: %v", combo.encryptor, err)
			}

			writeArtifact(t, artifactDir, comboName+"_plaintext.txt", plaintext)
			writeArtifact(t, artifactDir, comboName+"_ciphertext.ztdf", ztdfBytes)
			fmt.Printf("[cross-sdk] %s produced ZTDF (%d bytes)\n", comboName, len(ztdfBytes))

			decReq := sdkRequest{
				Ztdf:         encResp.Ztdf,
				Resource:     cfg.resource,
				PolicyBase64: cfg.policyBase64,
			}
			decResp := runSdkCommand(t, runners[combo.decryptor], "decrypt", decReq, paths)
			if decResp.Plaintext == "" {
				t.Fatalf("%s decrypt returned empty plaintext", combo.decryptor)
			}

			decrypted, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
			if err != nil {
				t.Fatalf("failed to decode plaintext from %s: %v", combo.decryptor, err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
			}
			writeArtifact(t, artifactDir, comboName+"_decrypted.txt", decrypted)
			fmt.Printf("[cross-sdk] %s verified successfully\n", comboName)
		})
	}
}

func runSdkCommand(t *testing.T, runner sdkRunner, mode string, req sdkRequest, paths projectPaths) sdkResponse {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	cmd := runner.buildCmd(mode)
	cmd.Stdin = bytes.NewReader(data)

	env := append([]string{}, os.Environ()...)
	env = append(env, runner.env...)
	if runner.javaRunner && paths.javaHome != "" {
		javaBin := filepath.Join(paths.javaHome, "bin")
		env = append(env, "JAVA_HOME="+paths.javaHome)
		env = append(env, fmt.Sprintf("PATH=%s%s%s", javaBin, string(os.PathListSeparator), os.Getenv("PATH")))
	}
	cmd.Env = env

	fmt.Printf("[cross-sdk] invoking %s %s with env overrides: %v\n", runner.name, mode, runner.env)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s command failed: %v\nstderr:\n%s", runner.name, mode, err, stderr.String())
	}

	var resp sdkResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse %s response: %v\nraw output: %s", runner.name, err, stdout.String())
	}
	return resp
}

type projectPaths struct {
	goDir    string
	javaDir  string
	jsDir    string
	javaHome string
	repoRoot string
}

func resolvePaths(t *testing.T) projectPaths {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to resolve working directory: %v", err)
	}

	goDir := filepath.Dir(wd)
	repoRoot := filepath.Dir(filepath.Dir(goDir))

	return projectPaths{
		goDir:    goDir,
		javaDir:  filepath.Join(repoRoot, "sdk", "java"),
		jsDir:    filepath.Join(repoRoot, "sdk", "js"),
		javaHome: detectJavaHome(),
		repoRoot: repoRoot,
	}
}

func detectJavaHome() string {
	if custom := os.Getenv("STRATIUM_JAVA_HOME"); custom != "" {
		return custom
	}

	if runtime.GOOS == "darwin" {
		out, err := exec.Command("/usr/libexec/java_home", "-v", "21").Output()
		if err == nil {
			if home := strings.TrimSpace(string(out)); home != "" {
				return home
			}
		}
	}

	if envHome := os.Getenv("JAVA_HOME"); envHome != "" {
		return envHome
	}
	return ""
}

func loadIntegrationConfig(paths projectPaths) (integrationConfig, string) {
	policy := strings.TrimSpace(os.Getenv("STRATIUM_POLICY_BASE64"))
	if policy == "" {
		return integrationConfig{}, "STRATIUM_POLICY_BASE64 is not set"
	}

	keyRoot := filepath.Join(paths.repoRoot, "artifacts", "client-keys")
	goKeyDir := filepath.Join(keyRoot, "go")
	jsKeyDir := filepath.Join(keyRoot, "js")
	_ = os.MkdirAll(goKeyDir, 0o700)
	_ = os.MkdirAll(jsKeyDir, 0o700)

	return integrationConfig{
		resource:     envOrDefault("STRATIUM_RESOURCE", "integration-resource"),
		filename:     envOrDefault("STRATIUM_FILENAME", "interop.txt"),
		contentType:  envOrDefault("STRATIUM_CONTENT_TYPE", "text/plain"),
		policyBase64: policy,
		goKeyDir:     goKeyDir,
		jsKeyDir:     jsKeyDir,
	}, ""
}

func envOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func writeArtifact(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write artifact %s: %v", path, err)
	}
	fmt.Printf("[cross-sdk] wrote %s (%d bytes)\n", path, len(data))
}
